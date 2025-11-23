package ratchet

import (
	"github.com/go-i2p/crypto/kdf"
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
type Session struct {
	dhRatchet  *DHRatchet
	symRatchet *SymmetricRatchet
	tagRatchet *TagRatchet
	messageNum uint32
}

// HandshakeResult contains the output of an ECIES key exchange handshake
type HandshakeResult struct {
	SharedSecret [32]byte // The ECIES-X25519 shared secret
	OurPrivKey   [32]byte // Our ephemeral private key
	TheirPubKey  [32]byte // Their public key
}

// NewSessionFromECIES creates a new session initialized from an ECIES shared secret.
// The shared secret is used as input to HKDF to derive all ratchet keys.
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
	log.Debug("Creating new session from ECIES shared secret")

	// Derive root key and initial chain keys from shared secret using kdf package
	kd := kdf.NewKeyDerivation(sharedSecret)
	rootKey, symChainKey, tagChainKey, err := kd.DeriveSessionKeys()
	if err != nil {
		return nil, oops.Wrapf(ErrKeyDerivationFailed, "failed to derive session keys: %w", err)
	}

	// Initialize ratchets
	dhRatchet := NewDHRatchet(rootKey, ourPrivKey, theirPubKey)
	symRatchet := NewSymmetricRatchet(symChainKey)
	tagRatchet := NewTagRatchet(tagChainKey)

	log.Debug("Session created successfully from ECIES shared secret")

	return &Session{
		dhRatchet:  dhRatchet,
		symRatchet: symRatchet,
		tagRatchet: tagRatchet,
		messageNum: 0,
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
	log.WithField("plaintext_len", len(plaintext)).
		WithField("message_num", s.messageNum).
		Debug("Encrypting message")

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

	log.WithField("session_tag", tag).
		Debug("Message encrypted successfully")

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
	log.WithField("session_tag", tag).
		WithField("message_num", s.messageNum).
		Debug("Decrypting message")

	// Verify tag matches expected tag
	expectedTag, err := s.tagRatchet.PeekNextTag()
	if err != nil {
		return messageKey, oops.Wrapf(err, "failed to peek session tag")
	}

	if expectedTag != tag {
		log.WithField("expected_tag", expectedTag).
			WithField("received_tag", tag).
			Warn("Session tag mismatch")
		return messageKey, oops.Errorf("invalid session tag: tag mismatch")
	}

	// Advance tag ratchet
	if err := s.tagRatchet.Advance(); err != nil {
		return messageKey, oops.Wrapf(err, "failed to advance tag ratchet")
	}

	// Derive message key
	messageKey, err = s.symRatchet.DeriveMessageKey(s.messageNum)
	if err != nil {
		return messageKey, oops.Wrapf(err, "failed to derive message key")
	}

	// Advance symmetric ratchet
	if err := s.symRatchet.Advance(); err != nil {
		return messageKey, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}

	// Increment message number
	s.messageNum++

	log.Debug("Message decrypted successfully")

	return messageKey, nil
}

// PerformDHRatchet performs a Diffie-Hellman ratchet step to derive new chain keys.
// This should be called periodically to maintain forward secrecy.
//
// Returns:
//   - sendingKey: New chain key for sending messages
//   - receivingKey: New chain key for receiving messages
//   - error: Any error during ratchet operation
//
// Example:
//
//	// Periodically refresh keys
//	sendKey, recvKey, err := session.PerformDHRatchet()
//	if err != nil {
//	    return err
//	}
func (s *Session) PerformDHRatchet() (sendingKey, receivingKey [32]byte, err error) {
	log.Debug("Performing DH ratchet")

	sendingKey, receivingKey, err = s.dhRatchet.PerformRatchet()
	if err != nil {
		return sendingKey, receivingKey, err
	}

	// Update symmetric ratchet with new sending chain key
	s.symRatchet = NewSymmetricRatchet(sendingKey)

	log.Debug("DH ratchet completed successfully")

	return sendingKey, receivingKey, nil
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
	log.Debug("Updating remote public key")
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

	log.Debug("Session state cleared")
}
