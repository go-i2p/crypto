package ratchet

import (
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Session combines DH ratchet, symmetric ratchet, and tag ratchet into a single
// coherent unit for ECIES-X25519-AEAD-Ratchet protocol. This provides a unified
// API for I2P garlic message encryption with forward secrecy.
//
// The Session handles:
//   - DH ratchet for periodic key agreement
//   - Symmetric ratchet for deriving message encryption keys
//   - Tag ratchet for session tag generation
//
// All ratchets are initialized from the same root key derived from ECIES shared secret.
//
// Per the I2P ECIES spec (section 4), the DH ratchet is bidirectional: each
// direction maintains its own root key, and after each DH ratchet step the
// resulting chain key is split via the TagAndKeyGenKeys KDF into a session tag
// chain key and a symmetric message key chain key.
type Session struct {
	dhRatchet  *DHRatchet
	symRatchet *SymmetricRatchet
	tagRatchet *TagRatchet
	messageNum uint32

	// sendingRootKey is the root key for the sending direction, used as the
	// input to DH_INITIALIZE on the next DH ratchet step.
	sendingRootKey [ChainKeySize]byte
	// receivingRootKey is the root key for the receiving direction.
	receivingRootKey [ChainKeySize]byte

	// lookaheadSize is the receiver look-ahead window size for session tag
	// validation (spec section 4b: "N might be at most 128, but 32 or even
	// less may be a better choice"). Defaults to DefaultLookaheadWindow.
	lookaheadSize int
	// lookaheadTags holds pre-computed session tags for out-of-order delivery
	// tolerance. Index i is the tag at offset i from the current ratchet
	// position. Rebuilt after each successful verification and DH ratchet.
	lookaheadTags [][SessionTagSize]byte
}

// HandshakeResult contains the output of an ECIES key exchange handshake
type HandshakeResult struct {
	SharedSecret [32]byte // The ECIES-X25519 shared secret
	OurPrivKey   [32]byte // Our ephemeral private key
	TheirPubKey  [32]byte // Their public key
}

// NewSessionFromECIES creates a new session initialized from an ECIES shared secret.
//
// The shared secret plays the role of "k" in the spec's DH INITIALIZATION KDF
// (section 4), with a zero initial root key:
//
//	keydata = HKDF(salt=rootKey, ikm=k, info="KDFDHRatchetStep", 64)
//	nextRootKey = keydata[0:32]
//	ck          = keydata[32:64]
//
// The chain key is then split via the TagAndKeyGenKeys KDF:
//
//	keydata = HKDF(salt=ck, ikm=ZEROLEN, info="TagAndKeyGenKeys", 64)
//	sessTag_ck = keydata[0:32]
//	symmKey_ck = keydata[32:64]
//
// This is the recommended way to create a session after ECIES key exchange.
//
// Parameters:
//   - sharedSecret: The 32-byte ECIES-X25519 shared secret
//   - ourPrivKey: Our ephemeral private key (for DH ratchet)
//   - theirPubKey: Their public key (for DH ratchet)
//
// Returns:
//   - *Session: The initialized session ready for message encryption
//   - error: Any error during key derivation
//
// Example:
//
//	// After ECIES key exchange
//	session, err := ratchet.NewSessionFromECIES(sharedSecret, ourPriv, theirPub)
//	if err != nil {
//	    return err
//	}
//	defer session.Zero()
//
//	// Encrypt message
//	ciphertext, tag, _ := session.EncryptMessage(plaintext)
func NewSessionFromECIES(sharedSecret, ourPrivKey, theirPubKey [32]byte) (*Session, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "NewSessionFromECIES"}).Debug("Creating new session from ECIES shared secret")

	// DH INITIALIZATION KDF (spec section 4): the shared secret plays the role
	// of "k" with a zero initial root key.
	var zeroRootKey [ChainKeySize]byte
	nextRootKey, ck, err := DH_INITIALIZEFull(zeroRootKey, sharedSecret)
	if err != nil {
		return nil, oops.Wrapf(ErrKeyDerivationFailed, "failed to run DH INITIALIZATION KDF: %w", err)
	}

	// TagAndKeyGenKeys KDF: split the chain key into the session tag chain key
	// and the symmetric key chain key.
	keydata, err := kdf.StandardHKDF(ck[:], nil, []byte("TagAndKeyGenKeys"), 64)
	if err != nil {
		return nil, oops.Wrapf(ErrKeyDerivationFailed, "failed to run TagAndKeyGenKeys KDF: %w", err)
	}
	var sessTagCK, symmKeyCK [ChainKeySize]byte
	copy(sessTagCK[:], keydata[0:32])
	copy(symmKeyCK[:], keydata[32:64])

	// Initialize ratchets
	dhRatchet := NewDHRatchet(nextRootKey, ourPrivKey, theirPubKey)
	symRatchet := NewSymmetricRatchet(symmKeyCK)
	tagRatchet := NewTagRatchet(sessTagCK)

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "NewSessionFromECIES"}).Debug("Session created successfully from ECIES shared secret")

	return &Session{
		dhRatchet:        dhRatchet,
		symRatchet:       symRatchet,
		tagRatchet:       tagRatchet,
		messageNum:       0,
		sendingRootKey:   nextRootKey,
		receivingRootKey: nextRootKey,
		lookaheadSize:    DefaultLookaheadWindow,
	}, nil
}

// NewSessionFromHandshake creates a new session from a handshake result.
// This is a convenience wrapper around NewSessionFromECIES.
//
// Parameters:
//   - handshake: The result of an ECIES key exchange
//
// Returns:
//   - *Session: The initialized session
//   - error: Any error during session creation
//
// Example:
//
//	handshake := HandshakeResult{
//	    SharedSecret: eciesSharedSecret,
//	    OurPrivKey:   ourEphemeralPriv,
//	    TheirPubKey:  theirStaticPub,
//	}
//	session, err := ratchet.NewSessionFromHandshake(handshake)
func NewSessionFromHandshake(handshake HandshakeResult) (*Session, error) {
	return NewSessionFromECIES(
		handshake.SharedSecret,
		handshake.OurPrivKey,
		handshake.TheirPubKey,
	)
}

// EncryptMessage encrypts a message and returns ciphertext with session tag.
// This method:
//  1. Generates a unique session tag for this message
//  2. Derives a message encryption key from the symmetric ratchet
//  3. Advances both ratchets for forward secrecy
//
// The returned session tag should be sent with the ciphertext to allow
// the recipient to identify which session to use for decryption.
//
// Parameters:
//   - plaintext: The message to encrypt
//
// Returns:
//   - messageKey: The 32-byte encryption key to use with ChaCha20-Poly1305
//   - tag: The 8-byte session tag
//   - error: Any error during encryption
//
// Example:
//
//	messageKey, sessionTag, err := session.EncryptMessage(plaintext)
//	if err != nil {
//	    return err
//	}
//
//	// Use messageKey with ChaCha20-Poly1305 AEAD
//	aead, _ := chacha20poly1305.NewAEAD(messageKey)
//	ciphertext, authTag, _ := aead.Encrypt(plaintext, sessionTag[:], nonce)
func (s *Session) EncryptMessage(plaintext []byte) (messageKey [32]byte, tag [8]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.EncryptMessage", "plaintext_len": len(plaintext), "message_num": s.messageNum}).Debug("Encrypting message")

	// The spec caps each tag set at 65535 messages; beyond that the DH ratchet
	// must be performed to obtain a fresh tag set.
	if s.messageNum >= MaxMessagesPerTagset {
		return messageKey, tag, ErrTagsetExhausted
	}

	// Generate session tag for this message
	tag, err = s.tagRatchet.GenerateNextTag()
	if err != nil {
		return messageKey, tag, oops.Wrapf(err, "failed to generate session tag")
	}

	// Derive message encryption key
	messageKey, err = s.symRatchet.DeriveMessageKey(s.messageNum)
	if err != nil {
		return messageKey, tag, oops.Wrapf(err, "failed to derive message key")
	}

	// Advance symmetric ratchet for forward secrecy
	if err := s.symRatchet.Advance(); err != nil {
		return messageKey, tag, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}

	// Increment message number
	s.messageNum++

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.EncryptMessage", "session_tag": tag}).Debug("Message encrypted successfully")

	return messageKey, tag, nil
}

// DecryptMessage prepares to decrypt a message by deriving the message key.
// This method verifies the session tag and derives the appropriate message key.
//
// Parameters:
//   - tag: The 8-byte session tag received with the ciphertext
//
// Returns:
//   - messageKey: The 32-byte decryption key to use with ChaCha20-Poly1305
//   - error: Any error if the tag is invalid
//
// Example:
//
//	messageKey, err := session.DecryptMessage(sessionTag)
//	if err != nil {
//	    return err
//	}
//
//	// Use messageKey with ChaCha20-Poly1305 AEAD
//	aead, _ := chacha20poly1305.NewAEAD(messageKey)
//	plaintext, _ := aead.Decrypt(ciphertext, authTag, sessionTag[:], nonce)
func (s *Session) DecryptMessage(tag [8]byte) (messageKey [32]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.DecryptMessage", "session_tag": tag, "message_num": s.messageNum}).Debug("Decrypting message")

	if err := s.verifySessionTag(tag); err != nil {
		return messageKey, err
	}

	messageKey, err = s.deriveDecryptionKey()
	if err != nil {
		return messageKey, err
	}

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.DecryptMessage"}).Debug("Message decrypted successfully")

	return messageKey, nil
}

// verifySessionTag validates that the received tag matches one of the
// pre-computed lookahead tags. Per the spec (section 4), receivers should
// implement a look-ahead strategy: the receiver ratchets ahead by the window
// size and stores the tags, so that out-of-order delivery within the window
// can still be decrypted.
//
// On a match at offset i, the tag ratchet is advanced i times to reach the
// matched position, and the lookahead window is rebuilt from there.
func (s *Session) verifySessionTag(tag [8]byte) error {
	if len(s.lookaheadTags) == 0 {
		s.rebuildLookahead()
	}

	for i, candidate := range s.lookaheadTags {
		if candidate != tag {
			continue
		}

		// Advance the tag ratchet to the matched position.
		for j := 0; j < i; j++ {
			if err := s.tagRatchet.Advance(); err != nil {
				return oops.Wrapf(err, "failed to advance tag ratchet")
			}
		}

		// Rebuild the window from the new position.
		s.rebuildLookahead()
		return nil
	}

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.verifySessionTag", "received_tag": tag}).Warn("Session tag not in lookahead window")
	return oops.Errorf("invalid session tag: tag mismatch")
}

// rebuildLookahead pre-computes the lookahead window of session tags. Index i
// of s.lookaheadTags is the tag at offset i from the current ratchet position
// (i.e., the tag that would be generated after i more Advance steps).
func (s *Session) rebuildLookahead() {
	size := s.lookaheadSize
	if size <= 0 {
		size = DefaultLookaheadWindow
	}
	if size > MaxLookaheadWindow {
		size = MaxLookaheadWindow
	}

	// Walk a copy of the tag ratchet so the real ratchet is not advanced.
	probe := *s.tagRatchet
	tags := make([][SessionTagSize]byte, 0, size)
	for i := 0; i < size; i++ {
		tag, err := probe.PeekNextTag()
		if err != nil {
			break
		}
		tags = append(tags, tag)
		if err := probe.Advance(); err != nil {
			break
		}
	}

	s.lookaheadTags = tags
}

// deriveDecryptionKey derives the message key and advances the symmetric ratchet.
func (s *Session) deriveDecryptionKey() ([32]byte, error) {
	var messageKey [32]byte

	messageKey, err := s.symRatchet.DeriveMessageKey(s.messageNum)
	if err != nil {
		return messageKey, oops.Wrapf(err, "failed to derive message key")
	}

	if err := s.symRatchet.Advance(); err != nil {
		return messageKey, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}

	s.messageNum++

	return messageKey, nil
}

// PerformDHRatchet performs a Diffie-Hellman ratchet step in the sending
// direction to derive a new tag set. This should be called periodically to
// maintain forward secrecy.
//
// Per the spec (section 4, DH RATCHET KDF + DH INITIALIZATION KDF), the chain
// key output of DH_INITIALIZE is split via the TagAndKeyGenKeys KDF:
//
//	keydata = HKDF(salt=ck, ikm=ZEROLEN, info="TagAndKeyGenKeys", 64)
//	sessTag_ck = keydata[0:32]
//	symmKey_ck = keydata[32:64]
//
// The session's symmetric and tag ratchets are reinitialized from the split,
// and the sending-direction root key is advanced.
//
// Returns:
//   - chainKey: The DH chain key (ck) output of DH_INITIALIZE
//   - nextRootKey: The new root key for the sending direction
//   - error: Any error during ratchet operation
//
// Example:
//
//	// Periodically refresh keys
//	ck, nextRootKey, err := session.PerformDHRatchet()
//	if err != nil {
//	    return err
//	}
func (s *Session) PerformDHRatchet() (chainKey, nextRootKey [32]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.PerformDHRatchet"}).Debug("Performing DH ratchet")

	// Select the sending-direction root key before the ratchet step.
	s.dhRatchet.SetRootKey(s.sendingRootKey)

	nextRootKey, ck, err := s.dhRatchet.PerformRatchet()
	if err != nil {
		return chainKey, nextRootKey, err
	}
	chainKey = ck

	// TagAndKeyGenKeys KDF: split the chain key into the session tag chain key
	// and the symmetric key chain key.
	keydata, err := kdf.StandardHKDF(ck[:], nil, []byte("TagAndKeyGenKeys"), 64)
	if err != nil {
		return chainKey, nextRootKey, oops.Wrapf(ErrKeyDerivationFailed, "failed to run TagAndKeyGenKeys KDF: %w", err)
	}
	var sessTagCK, symmKeyCK [ChainKeySize]byte
	copy(sessTagCK[:], keydata[0:32])
	copy(symmKeyCK[:], keydata[32:64])

	// Reinitialize the ratchets from the split and advance the root key.
	s.symRatchet = NewSymmetricRatchet(symmKeyCK)
	s.tagRatchet = NewTagRatchet(sessTagCK)
	s.sendingRootKey = nextRootKey
	s.messageNum = 0
	s.rebuildLookahead()

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.PerformDHRatchet"}).Debug("DH ratchet completed successfully")

	return chainKey, nextRootKey, nil
}

// UpdateRemotePublicKey updates the remote party's public key for DH ratchet.
// This is used when the remote party rotates their ephemeral key.
//
// Parameters:
//   - newPubKey: The new remote public key
//
// Returns:
//   - error: Any error during key update
func (s *Session) UpdateRemotePublicKey(newPubKey [32]byte) error {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.UpdateRemotePublicKey"}).Debug("Updating remote public key")
	return s.dhRatchet.UpdateKeys(newPubKey[:])
}

// GetNextTag returns the next expected session tag without advancing the ratchet.
// This is useful for tag validation and session lookup.
//
// Returns:
//   - [8]byte: The next expected session tag
func (s *Session) GetNextTag() ([8]byte, error) {
	return s.tagRatchet.PeekNextTag()
}

// GetMessageNumber returns the current message number.
func (s *Session) GetMessageNumber() uint32 {
	return s.messageNum
}

// Zero securely clears all session state from memory.
// This should be called when the session is no longer needed.
func (s *Session) Zero() {
	if s.dhRatchet != nil {
		s.dhRatchet.Zero()
	}
	if s.symRatchet != nil {
		s.symRatchet.Zero()
	}
	if s.tagRatchet != nil {
		s.tagRatchet.Zero()
	}
	s.messageNum = 0
	s.sendingRootKey = [ChainKeySize]byte{}
	s.receivingRootKey = [ChainKeySize]byte{}
	for i := range s.lookaheadTags {
		s.lookaheadTags[i] = [SessionTagSize]byte{}
	}
	s.lookaheadTags = nil

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.Zero"}).Debug("Session state cleared")
}
