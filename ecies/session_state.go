// Package ecies session state management for ECIES-X25519-AEAD-Ratchet protocol.
package ecies

import (
	"crypto/rand"
	"io"
	"sync"

	"github.com/go-i2p/crypto/ratchet"
	"github.com/samber/oops"
)

// SessionState tracks the state of an ECIES session with forward secrecy.
// It implements the three-level ratcheting mechanism from I2P Proposal 144:
// 1. Session Tag Ratchet - Derives unique session tags for message routing
// 2. Symmetric Key Ratchet - Derives message encryption keys
// 3. DH Ratchet - Provides forward secrecy through ephemeral key exchanges
type SessionState struct {
	mu sync.RWMutex // Protects concurrent access to session state

	// Session identification
	SessionID [32]byte

	// Static keys
	LocalPrivKey       [32]byte // Our static private key
	RemoteStaticPubKey [32]byte // Remote peer's static public key

	// Ratchet state - Sending chain
	SendingChainKey   [32]byte // Current sending chain key
	SendingMessageNum uint32   // Next message number to send

	// Ratchet state - Receiving chain
	ReceivingChainKey   [32]byte // Current receiving chain key
	ReceivingMessageNum uint32   // Next expected message number

	// DH Ratchet state
	DHRatchetPrivKey [32]byte // Our current DH ratchet private key
	DHRatchetPubKey  [32]byte // Our current DH ratchet public key
	RemoteDHPubKey   [32]byte // Remote peer's current DH ratchet public key

	// Session tag ratchets
	SendingTagRatchet   *ratchet.TagRatchet // Derives outgoing session tags
	ReceivingTagRatchet *ratchet.TagRatchet // Derives incoming session tags

	// Previous chain length for message ordering
	PreviousChainLength uint32

	// Session creation timestamp
	CreatedAt int64
}

// NewSession creates a new ECIES session state.
// localPrivKey: Our static X25519 private key (32 bytes)
// remoteStaticPubKey: Remote peer's static X25519 public key (32 bytes)
// isInitiator: True if we are initiating the session, false if responding
func NewSession(localPrivKey, remoteStaticPubKey []byte, isInitiator bool) (*SessionState, error) {
	if len(localPrivKey) != PrivateKeySize {
		return nil, oops.Errorf("invalid local private key size: expected %d, got %d", PrivateKeySize, len(localPrivKey))
	}
	if len(remoteStaticPubKey) != PublicKeySize {
		return nil, oops.Errorf("invalid remote public key size: expected %d, got %d", PublicKeySize, len(remoteStaticPubKey))
	}

	session := &SessionState{}
	copy(session.LocalPrivKey[:], localPrivKey)
	copy(session.RemoteStaticPubKey[:], remoteStaticPubKey)

	// Generate session ID from random bytes
	if _, err := io.ReadFull(rand.Reader, session.SessionID[:]); err != nil {
		return nil, oops.Errorf("failed to generate session ID: %w", err)
	}

	// Initialize DH ratchet with a fresh ephemeral key pair
	if err := session.initializeDHRatchet(); err != nil {
		return nil, oops.Errorf("failed to initialize DH ratchet: %w", err)
	}

	// Derive initial chain keys from static DH
	if err := session.deriveInitialKeys(isInitiator); err != nil {
		return nil, oops.Errorf("failed to derive initial keys: %w", err)
	}

	// Initialize session tag ratchets
	session.SendingTagRatchet = ratchet.NewTagRatchet(session.SendingChainKey)
	session.ReceivingTagRatchet = ratchet.NewTagRatchet(session.ReceivingChainKey)

	session.CreatedAt = currentTimestamp()

	log.WithField("session_id", session.SessionID[:8]).Debug("ECIES session created")
	return session, nil
}

// initializeDHRatchet generates a fresh ephemeral key pair for the DH ratchet.
func (s *SessionState) initializeDHRatchet() error {
	pubKey, privKey, err := GenerateKeyPair()
	if err != nil {
		return err
	}

	copy(s.DHRatchetPubKey[:], pubKey)
	copy(s.DHRatchetPrivKey[:], privKey)

	return nil
}

// deriveInitialKeys performs initial key derivation from static DH.
// The derivation differs for initiator vs responder to ensure both peers
// use different keys for sending/receiving.
func (s *SessionState) deriveInitialKeys(isInitiator bool) error {
	// Perform static X25519 DH
	sharedSecret, err := performDH(s.LocalPrivKey[:], s.RemoteStaticPubKey[:])
	if err != nil {
		return err
	}

	// Derive root key and initial chain keys using HKDF
	// Info string distinguishes initiator from responder
	var info string
	if isInitiator {
		info = "ECIES-Session-Initiator"
	} else {
		info = "ECIES-Session-Responder"
	}

	// Derive 64 bytes: sending key (32) + receiving key (32)
	keys, err := deriveKeys(sharedSecret, []byte(info), 64)
	if err != nil {
		return err
	}

	if isInitiator {
		// Initiator: first 32 bytes = sending, second 32 = receiving
		copy(s.SendingChainKey[:], keys[:32])
		copy(s.ReceivingChainKey[:], keys[32:64])
	} else {
		// Responder: opposite arrangement
		copy(s.ReceivingChainKey[:], keys[:32])
		copy(s.SendingChainKey[:], keys[32:64])
	}

	return nil
}

// DeriveNextSendingKey derives the next message encryption key from the sending chain.
// This implements the symmetric key ratchet for sending.
func (s *SessionState) DeriveNextSendingKey() ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	messageKey, newChainKey, err := ratchet.RatchetSymmetricKey(s.SendingChainKey, s.SendingMessageNum)
	if err != nil {
		return [32]byte{}, err
	}

	// Update chain key and increment message number
	s.SendingChainKey = newChainKey
	s.SendingMessageNum++

	log.WithField("message_num", s.SendingMessageNum-1).Debug("Derived sending key")
	return messageKey, nil
}

// DeriveNextReceivingKey derives the next message decryption key from the receiving chain.
// This implements the symmetric key ratchet for receiving.
func (s *SessionState) DeriveNextReceivingKey() ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	messageKey, newChainKey, err := ratchet.RatchetSymmetricKey(s.ReceivingChainKey, s.ReceivingMessageNum)
	if err != nil {
		return [32]byte{}, err
	}

	// Update chain key and increment message number
	s.ReceivingChainKey = newChainKey
	s.ReceivingMessageNum++

	log.WithField("message_num", s.ReceivingMessageNum-1).Debug("Derived receiving key")
	return messageKey, nil
}

// PerformDHRatchet performs a DH ratchet step, providing forward secrecy.
// This should be called when we receive a new DH public key from the remote peer.
func (s *SessionState) PerformDHRatchet(remoteDHPubKey []byte) error {
	if len(remoteDHPubKey) != PublicKeySize {
		return oops.Errorf("invalid remote DH public key size: expected %d, got %d", PublicKeySize, len(remoteDHPubKey))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Perform DH with remote's new public key
	sharedSecret, err := performDH(s.DHRatchetPrivKey[:], remoteDHPubKey)
	if err != nil {
		return oops.Errorf("DH ratchet key agreement failed: %w", err)
	}

	// Derive new chain keys from DH output
	keys, err := deriveKeys(sharedSecret, []byte("ECIES-DH-Ratchet"), 64)
	if err != nil {
		return oops.Errorf("DH ratchet key derivation failed: %w", err)
	}

	// Update receiving chain (we receive with new remote DH key)
	copy(s.ReceivingChainKey[:], keys[:32])
	s.PreviousChainLength = s.SendingMessageNum
	s.ReceivingMessageNum = 0

	// Update sending chain (we send with our existing DH key)
	copy(s.SendingChainKey[:], keys[32:64])
	s.SendingMessageNum = 0

	// Store remote's new DH public key
	copy(s.RemoteDHPubKey[:], remoteDHPubKey)

	// Generate a new ephemeral key pair for the next ratchet step
	if err := s.initializeDHRatchet(); err != nil {
		return oops.Errorf("failed to generate new DH ratchet key: %w", err)
	}

	// Update tag ratchets with new chain keys
	s.SendingTagRatchet = ratchet.NewTagRatchet(s.SendingChainKey)
	s.ReceivingTagRatchet = ratchet.NewTagRatchet(s.ReceivingChainKey)

	log.WithField("remote_dh_key", remoteDHPubKey[:8]).Debug("DH ratchet performed")
	return nil
}

// GetNextSendingTag derives the next session tag for sending an existing session message.
func (s *SessionState) GetNextSendingTag() ([8]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tag, err := s.SendingTagRatchet.GenerateNextTag()
	if err != nil {
		return [8]byte{}, oops.Errorf("failed to generate sending tag: %w", err)
	}

	log.WithField("tag", tag[:]).Debug("Generated sending tag")
	return tag, nil
}

// ValidateReceivingTag checks if a received tag matches the expected tag in the receiving ratchet.
func (s *SessionState) ValidateReceivingTag(tag [8]byte) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// For now, generate the expected tag and compare
	// A production implementation would maintain a window of valid tags
	expectedTag, err := s.ReceivingTagRatchet.PeekNextTag()
	if err != nil {
		return false, err
	}

	matches := constantTimeEqual(tag[:], expectedTag[:])
	if matches {
		// Advance the ratchet on successful match
		s.mu.RUnlock()
		s.mu.Lock()
		_, _ = s.ReceivingTagRatchet.GenerateNextTag()
		s.mu.Unlock()
		s.mu.RLock()
	}

	return matches, nil
}

// GetSessionID returns the session identifier.
func (s *SessionState) GetSessionID() [32]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.SessionID
}

// GetDHRatchetPublicKey returns our current DH ratchet public key.
func (s *SessionState) GetDHRatchetPublicKey() [32]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.DHRatchetPubKey
}

// Zero securely clears sensitive session data from memory.
func (s *SessionState) Zero() {
	s.mu.Lock()
	defer s.mu.Unlock()

	zeroBytes(s.SessionID[:])
	zeroBytes(s.LocalPrivKey[:])
	zeroBytes(s.RemoteStaticPubKey[:])
	zeroBytes(s.SendingChainKey[:])
	zeroBytes(s.ReceivingChainKey[:])
	zeroBytes(s.DHRatchetPrivKey[:])
	zeroBytes(s.DHRatchetPubKey[:])
	zeroBytes(s.RemoteDHPubKey[:])

	if s.SendingTagRatchet != nil {
		s.SendingTagRatchet.Zero()
	}
	if s.ReceivingTagRatchet != nil {
		s.ReceivingTagRatchet.Zero()
	}
}

// Helper function to zero a byte slice securely
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
