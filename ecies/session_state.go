// Package ecies session state management for ECIES-X25519-AEAD-Ratchet protocol.
package ecies

import (
	"crypto/rand"
	"io"
	"sync"

	"github.com/go-i2p/crypto/kdf"
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
	if err := validateSessionKeys(localPrivKey, remoteStaticPubKey); err != nil {
		return nil, err
	}

	session := createSessionWithKeys(localPrivKey, remoteStaticPubKey)

	// Generate session ID from random bytes
	if err := generateSessionID(session); err != nil {
		return nil, err
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
	initializeTagRatchets(session)

	session.CreatedAt = currentTimestamp()

	log.WithField("session_id", session.SessionID[:8]).Debug("ECIES session created")
	return session, nil
}

// validateSessionKeys checks that the provided keys have the correct sizes.
func validateSessionKeys(localPrivKey, remoteStaticPubKey []byte) error {
	if len(localPrivKey) != PrivateKeySize {
		return oops.Errorf("invalid local private key size: expected %d, got %d", PrivateKeySize, len(localPrivKey))
	}
	if len(remoteStaticPubKey) != PublicKeySize {
		return oops.Errorf("invalid remote public key size: expected %d, got %d", PublicKeySize, len(remoteStaticPubKey))
	}
	return nil
}

// createSessionWithKeys creates a new session state and copies the provided keys.
func createSessionWithKeys(localPrivKey, remoteStaticPubKey []byte) *SessionState {
	session := &SessionState{}
	copy(session.LocalPrivKey[:], localPrivKey)
	copy(session.RemoteStaticPubKey[:], remoteStaticPubKey)
	return session
}

// generateSessionID generates a random session identifier using cryptographically secure random bytes.
func generateSessionID(session *SessionState) error {
	if _, err := io.ReadFull(rand.Reader, session.SessionID[:]); err != nil {
		return oops.Errorf("failed to generate session ID: %w", err)
	}
	return nil
}

// initializeTagRatchets creates and initializes the session tag ratchets for sending and receiving.
func initializeTagRatchets(session *SessionState) {
	session.SendingTagRatchet = ratchet.NewTagRatchet(session.SendingChainKey)
	session.ReceivingTagRatchet = ratchet.NewTagRatchet(session.ReceivingChainKey)
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
	sharedSecret, err := s.performStaticDH()
	if err != nil {
		return err
	}

	keys, err := deriveSessionChainKeys(sharedSecret, isInitiator)
	if err != nil {
		return err
	}

	s.assignChainKeysByRole(keys, isInitiator)
	return nil
}

// performStaticDH executes the static X25519 Diffie-Hellman key exchange.
func (s *SessionState) performStaticDH() ([]byte, error) {
	sharedSecret, err := performDH(s.LocalPrivKey[:], s.RemoteStaticPubKey[:])
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

// deriveSessionChainKeys derives sending and receiving chain keys using HKDF.
func deriveSessionChainKeys(sharedSecret []byte, isInitiator bool) ([][32]byte, error) {
	var info string
	if isInitiator {
		info = "ECIES-Session-Initiator"
	} else {
		info = "ECIES-Session-Responder"
	}

	var sharedSecretArray [32]byte
	copy(sharedSecretArray[:], sharedSecret)
	kd := kdf.NewKeyDerivation(sharedSecretArray)

	keys, err := kd.DeriveKeys([]byte(info), 2)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// assignChainKeysByRole assigns chain keys based on initiator or responder role.
func (s *SessionState) assignChainKeysByRole(keys [][32]byte, isInitiator bool) {
	if isInitiator {
		s.SendingChainKey = keys[0]
		s.ReceivingChainKey = keys[1]
	} else {
		s.ReceivingChainKey = keys[0]
		s.SendingChainKey = keys[1]
	}
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

	// Perform DH and derive new chain keys
	keys, err := performDHAndDeriveKeys(s.DHRatchetPrivKey[:], remoteDHPubKey)
	if err != nil {
		return err
	}

	// Update ratchet state with new keys
	s.updateRatchetChains(keys, remoteDHPubKey)

	// Generate a new ephemeral key pair for the next ratchet step
	if err := s.initializeDHRatchet(); err != nil {
		return oops.Errorf("failed to generate new DH ratchet key: %w", err)
	}

	// Update tag ratchets with new chain keys
	updateSessionTagRatchets(s)

	log.WithField("remote_dh_key", remoteDHPubKey[:8]).Debug("DH ratchet performed")
	return nil
}

// performDHAndDeriveKeys performs Diffie-Hellman key agreement and derives chain keys.
// Returns 2 keys as [32]byte arrays: receiving key and sending key.
func performDHAndDeriveKeys(localPrivKey, remotePubKey []byte) ([][32]byte, error) {
	// Perform DH with remote's new public key
	sharedSecret, err := performDH(localPrivKey, remotePubKey)
	if err != nil {
		return nil, oops.Errorf("DH ratchet key agreement failed: %w", err)
	}

	// Use kdf package for consistent derivation
	var sharedSecretArray [32]byte
	copy(sharedSecretArray[:], sharedSecret)
	kd := kdf.NewKeyDerivation(sharedSecretArray)

	// Derive new chain keys from DH output: receiving key + sending key
	keys, err := kd.DeriveKeys([]byte("ECIES-DH-Ratchet"), 2)
	if err != nil {
		return nil, oops.Errorf("DH ratchet key derivation failed: %w", err)
	}

	return keys, nil
}

// updateRatchetChains updates the sending and receiving chain keys after a DH ratchet.
// Resets message counters and stores the remote DH public key.
func (s *SessionState) updateRatchetChains(keys [][32]byte, remoteDHPubKey []byte) {
	// Update receiving chain (we receive with new remote DH key)
	s.ReceivingChainKey = keys[0]
	s.PreviousChainLength = s.SendingMessageNum
	s.ReceivingMessageNum = 0

	// Update sending chain (we send with our existing DH key)
	s.SendingChainKey = keys[1]
	s.SendingMessageNum = 0

	// Store remote's new DH public key
	copy(s.RemoteDHPubKey[:], remoteDHPubKey)
}

// updateSessionTagRatchets reinitializes the session tag ratchets with the current chain keys.
func updateSessionTagRatchets(s *SessionState) {
	s.SendingTagRatchet = ratchet.NewTagRatchet(s.SendingChainKey)
	s.ReceivingTagRatchet = ratchet.NewTagRatchet(s.ReceivingChainKey)
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
