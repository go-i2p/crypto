package ratchet

import (
	"encoding/binary"

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
	// lookahead holds the receiver's pre-computed window of (session tag,
	// message key) pairs for out-of-order delivery tolerance, as required by
	// spec sections 4b and 4c: the receiver ratchets its tag chain ahead by the
	// window size, and because the session tag ratchet is synchronized with the
	// symmetric key ratchet, each tag is paired with the message key derived at
	// the same position. Index i is the entry at offset i from the current
	// ratchet position. Rebuilt after each successful verification and DH
	// ratchet.
	lookahead []lookaheadEntry
}

// lookaheadEntry is one slot of the receiver's look-ahead window: the session
// tag on the wire, paired with the message key derived at the same ratchet
// position and the message number N for that slot. Advancing both chains
// together keeps the tag and symmetric key ratchets synchronized, as spec
// sections 4b and 4c require.
//
// N is stored alongside each tag because the spec makes the message number the
// ChaCha20-Poly1305 nonce: "n = The message number N in the current chain, as
// retrieved from the associated Session Tag" (section 1h). Without it a
// receiver could not rebuild the nonce for an out-of-order message.
type lookaheadEntry struct {
	tag  [SessionTagSize]byte
	key  [MessageKeySize]byte
	num  uint32
	used bool
}

// DataNonce builds the Existing Session AEAD nonce from a message number, per
// the I2P ECIES spec section 3: a 12-byte counter nonce whose first four bytes
// are always zero and whose last eight bytes are the message number n in
// little-endian order.
//
// The spec caps n at 65535 ("Higher values must never be used"); callers should
// enforce that through the tag-set limit rather than relying on this function.
func DataNonce(n uint32) [NonceSize]byte {
	var nonce [NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(n))
	return nonce
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
// # Limitation: the initial keys are not derived per the specification
//
// The spec obtains the initial ratchet inputs from the New Session Reply
// handshake: DH_INITIALIZE takes rootKey = "chainKey from Payload Section" and
// k = "from the New Session KDF or split()", and the two directions get
// separate tag sets ("The chainKey and k from Bob's NSR Payload Section are
// used as inputs for the initial ES DH Ratchets (both directions...)").
//
// This constructor has no handshake state to draw on, so it substitutes a
// zero root key with the caller's shared secret as k, and seeds both directions
// from the same result. The KDFs it then applies (KDFDHRatchetStep,
// TagAndKeyGenKeys, STInitialization, SessionTagKeyGen, SymmetricRatchet) are
// exactly the spec's, but the initial seed is not, so a session created here
// will not interoperate with a Java I2P router. Use it for local ratcheting and
// tests; for on-network sessions the keys must come from a spec-compliant
// New Session / New Session Reply handshake, which this package does not
// implement (see the ecies package docs for the scope boundary).
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
//	// Encrypt message: the session yields the per-message key, the session tag,
//	// and the spec's counter nonce; the caller does the ChaCha20-Poly1305
//	// encryption with them.
//	messageKey, tag, nonce, _ := session.EncryptMessage(plaintext)
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

// EncryptMessage advances the ratchets and returns the message key, session
// tag, and AEAD nonce for the next outbound message. This method:
//  1. Generates a unique session tag for this message
//  2. Derives a message encryption key from the symmetric ratchet
//  3. Computes the spec's counter nonce from the message number
//  4. Advances both ratchets for forward secrecy
//
// It does NOT itself encrypt the plaintext: the caller must use the returned
// messageKey and nonce with a ChaCha20-Poly1305 AEAD to produce the ciphertext,
// and send that ciphertext together with the returned session tag so the
// recipient can identify which session (and message) it belongs to. Per spec
// section 1h the session tag is the AEAD associated data.
//
// Parameters:
//   - plaintext: The message to derive a key for (used only for logging; the
//     caller encrypts it with the returned key)
//
// Returns:
//   - messageKey: The 32-byte encryption key to use with ChaCha20-Poly1305
//   - tag: The 8-byte session tag (also the AEAD associated data)
//   - nonce: The 12-byte counter nonce for this message
//   - error: Any error during encryption
//
// Example:
//
//	messageKey, sessionTag, nonce, err := session.EncryptMessage(plaintext)
//	if err != nil {
//	    return err
//	}
//
//	// Use messageKey with ChaCha20-Poly1305 AEAD
//	aead, _ := chacha20poly1305.NewAEAD(messageKey)
//	ciphertext, authTag, _ := aead.Encrypt(plaintext, sessionTag[:], nonce[:])
func (s *Session) EncryptMessage(plaintext []byte) (messageKey [32]byte, tag [8]byte, nonce [NonceSize]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.EncryptMessage", "plaintext_len": len(plaintext), "message_num": s.messageNum}).Debug("Encrypting message")

	// Spec §3: 65535 is the maximum valid message number, so a tag set carries
	// numbers 0..65535 (65536 messages); only beyond that is a DH ratchet step
	// required. Matches go-noise's MaxMessageNumber enforcement.
	if s.messageNum > MaxMessagesPerTagset {
		return messageKey, tag, nonce, ErrTagsetExhausted
	}

	// The AEAD nonce is this message's number in the chain (spec section 1h:
	// "n = The message number N in the current chain"), captured before the
	// counter is advanced.
	nonce = DataNonce(s.messageNum)

	// Generate session tag for this message
	tag, err = s.tagRatchet.GenerateNextTag()
	if err != nil {
		return messageKey, tag, nonce, oops.Wrapf(err, "failed to generate session tag")
	}

	// Derive message encryption key
	messageKey, err = s.symRatchet.DeriveMessageKey(s.messageNum)
	if err != nil {
		return messageKey, tag, nonce, oops.Wrapf(err, "failed to derive message key")
	}

	// Advance symmetric ratchet for forward secrecy
	if err := s.symRatchet.Advance(); err != nil {
		return messageKey, tag, nonce, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}

	// Increment message number
	s.messageNum++

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.EncryptMessage", "session_tag": tag}).Debug("Message encrypted successfully")

	return messageKey, tag, nonce, nil
}

// DecryptMessage looks up a received session tag in the receiver's look-ahead
// window and returns the message key and AEAD nonce associated with it.
//
// Tags are matched against the pre-computed window so that out-of-order delivery
// within the window still resolves to the correct key; the tag and symmetric key
// ratchets advance in lockstep as the contiguous head of the window is consumed.
//
// Parameters:
//   - tag: The 8-byte session tag received with the ciphertext
//
// Returns:
//   - messageKey: The 32-byte decryption key to use with ChaCha20-Poly1305
//   - nonce: The 12-byte counter nonce for this message's number
//   - error: Any error if the tag is invalid
//
// Example:
//
//	messageKey, nonce, err := session.DecryptMessage(sessionTag)
//	if err != nil {
//	    return err
//	}
//
//	// Use messageKey with ChaCha20-Poly1305 AEAD
//	aead, _ := chacha20poly1305.NewAEAD(messageKey)
//	plaintext, _ := aead.Decrypt(ciphertext, authTag, sessionTag[:], nonce[:])
func (s *Session) DecryptMessage(tag [8]byte) (messageKey [32]byte, nonce [NonceSize]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.DecryptMessage", "session_tag": tag, "message_num": s.messageNum}).Debug("Decrypting message")

	if len(s.lookahead) == 0 {
		s.rebuildLookahead()
	}

	idx := -1
	for i := range s.lookahead {
		if s.lookahead[i].tag == tag && !s.lookahead[i].used {
			idx = i
			break
		}
	}
	if idx < 0 {
		log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.DecryptMessage", "received_tag": tag}).Warn("Session tag not in lookahead window")
		return messageKey, nonce, oops.Errorf("invalid session tag: tag mismatch")
	}

	matched := s.lookahead[idx]
	s.lookahead[idx].used = true

	// Advance the real ratchets past the contiguous run of received messages at
	// the head of the window. Unreceived messages further along keep their
	// cached keys, so out-of-order delivery within the window still resolves to
	// the correct key (spec sections 4b and 4c: the receiver "should keep the
	// 'N' value associated with each session tag" and cache "the keys for any
	// previous tags that have not yet been received").
	for len(s.lookahead) > 0 && s.lookahead[0].used {
		if err := s.tagRatchet.Advance(); err != nil {
			return messageKey, nonce, oops.Wrapf(err, "failed to advance tag ratchet")
		}
		if err := s.symRatchet.Advance(); err != nil {
			return messageKey, nonce, oops.Wrapf(err, "failed to advance symmetric ratchet")
		}
		s.messageNum++
		s.lookahead = s.lookahead[1:]
	}
	s.fillLookahead()

	// The AEAD nonce is the matched message number (spec section 1h: "n = The
	// message number N in the current chain, as retrieved from the associated
	// Session Tag"). Returning it lets the caller decrypt an out-of-order
	// message, since the nonce is not otherwise recoverable from the tag.
	nonce = DataNonce(matched.num)

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.DecryptMessage"}).Debug("Message decrypted successfully")

	return matched.key, nonce, nil
}

// fillLookahead extends the receiver's look-ahead window back up to
// lookaheadSize entries by walking copies of the tag and symmetric ratchets.
// Existing (possibly already-received) entries are left untouched, so keys
// cached for out-of-order messages are not discarded.
func (s *Session) fillLookahead() {
	size := s.lookaheadSize
	if size <= 0 {
		size = DefaultLookaheadWindow
	}
	if size > MaxLookaheadWindow {
		size = MaxLookaheadWindow
	}
	if len(s.lookahead) >= size {
		return
	}

	// Walk copies so the real ratchet positions are not advanced.
	tagProbe := *s.tagRatchet
	symProbe := *s.symRatchet
	// Skip the entries already cached in the window.
	for i := 0; i < len(s.lookahead); i++ {
		if err := tagProbe.Advance(); err != nil {
			break
		}
		if err := symProbe.Advance(); err != nil {
			break
		}
	}

	for len(s.lookahead) < size {
		tag, err := tagProbe.PeekNextTag()
		if err != nil {
			break
		}
		key, err := symProbe.DeriveMessageKey(0)
		if err != nil {
			break
		}
		// The slot's message number is its absolute position in the chain: the
		// number the ratchet will reach once the existing entries are consumed.
		num := s.messageNum + uint32(len(s.lookahead))
		s.lookahead = append(s.lookahead, lookaheadEntry{tag: tag, key: key, num: num})
		if err := tagProbe.Advance(); err != nil {
			break
		}
		if err := symProbe.Advance(); err != nil {
			break
		}
	}
}

// rebuildLookahead discards and recomputes the whole look-ahead window from the
// current ratchet positions. Called when the ratchets are reinitialized (DH
// ratchet step) or the window is empty.
func (s *Session) rebuildLookahead() {
	s.lookahead = nil
	s.fillLookahead()
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
	// The look-ahead window caches per-message keys, so it must be zeroed too.
	for i := range s.lookahead {
		s.lookahead[i] = lookaheadEntry{}
	}
	s.lookahead = nil

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.Zero"}).Debug("Session state cleared")
}
