package ecies

import (
	"crypto/rand"
	"io"
	"sync"

	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SessionState tracks the state of an ECIES session with forward secrecy.
// It implements the three-level ratcheting mechanism from I2P Proposal 144:
// 1. Session Tag Ratchet - Derives unique session tags for message routing
// 2. Symmetric Key Ratchet - Derives message encryption keys
// 3. DH Ratchet - Provides forward secrecy through ephemeral key exchanges
//
// Deprecated: SessionState is a convenience API that does not fully conform
// to the I2P ECIES-X25519-AEAD-Ratchet specification
// (https://i2p.net/en/docs/specs/ecies/). The static-static key
// initialization and DH ratchet key derivation use non-spec KDF parameters.
// For spec-compliant ratcheted sessions, use ratchet.Session instead.
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

	// DH Ratchet root keys (per spec §4, each direction tracks its own root key)
	SendingRootKey   [32]byte // Root key for the sending direction's tag set
	ReceivingRootKey [32]byte // Root key for the receiving direction's tag set

	// Receiver lookahead window (spec §4: N ≤ 128, 32 recommended)
	receivingLookaheadTags [][ratchet.SessionTagSize]byte
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

	log.WithFields(logger.Fields{"pkg": "ecies", "func": "NewSession", "session_id": session.SessionID[:8]}).Debug("ECIES session created")
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

	// Initialize the per-direction root keys to zero (the spec's initial
	// DH_INITIALIZE input). They are advanced on each DH ratchet step.
	s.SendingRootKey = [32]byte{}
	s.ReceivingRootKey = [32]byte{}
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

// deriveSessionChainKeys derives sending and receiving chain keys using
// spec-convention HKDF (salt-first, per I2P Proposal 144 §1f).
//
// Note: the static-static initialization has no spec-defined chainKey seed,
// so the shared secret is used as the HKDF salt with an empty IKM. This is a
// pragmatic, non-spec derivation; see the SessionState deprecation notice.
func deriveSessionChainKeys(sharedSecret []byte, isInitiator bool) ([][32]byte, error) {
	var info string
	if isInitiator {
		info = "ECIES-Session-Initiator"
	} else {
		info = "ECIES-Session-Responder"
	}

	keydata, err := kdf.StandardHKDF(sharedSecret, nil, []byte(info), 64)
	if err != nil {
		return nil, err
	}

	// keydata is 64 bytes: the first 32 are the initiator chain key and the
	// last 32 are the responder chain key. Allocate both slots before writing.
	keys := make([][32]byte, 2)
	copy(keys[0][:], keydata[0:32])
	copy(keys[1][:], keydata[32:64])
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

	// Spec §4: the maximum number of messages before the DH must ratchet is 65535.
	if s.SendingMessageNum >= ratchet.MaxMessagesPerTagset {
		return [32]byte{}, ratchet.ErrTagsetExhausted
	}

	messageKey, newChainKey, err := ratchet.RatchetSymmetricKey(s.SendingChainKey, s.SendingMessageNum)
	if err != nil {
		return [32]byte{}, err
	}

	// Update chain key and increment message number
	s.SendingChainKey = newChainKey
	s.SendingMessageNum++

	log.WithFields(logger.Fields{"pkg": "ecies", "func": "SessionState.DeriveNextSendingKey", "message_num": s.SendingMessageNum - 1}).Debug("Derived sending key")
	return messageKey, nil
}

// DeriveNextReceivingKey derives the next message decryption key from the receiving chain.
// This implements the symmetric key ratchet for receiving.
func (s *SessionState) DeriveNextReceivingKey() ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Spec §4: the maximum number of messages before the DH must ratchet is 65535.
	if s.ReceivingMessageNum >= ratchet.MaxMessagesPerTagset {
		return [32]byte{}, ratchet.ErrTagsetExhausted
	}

	messageKey, newChainKey, err := ratchet.RatchetSymmetricKey(s.ReceivingChainKey, s.ReceivingMessageNum)
	if err != nil {
		return [32]byte{}, err
	}

	// Update chain key and increment message number
	s.ReceivingChainKey = newChainKey
	s.ReceivingMessageNum++

	log.WithFields(logger.Fields{"pkg": "ecies", "func": "SessionState.DeriveNextReceivingKey", "message_num": s.ReceivingMessageNum - 1}).Debug("Derived receiving key")
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

	// Perform DH and derive new chain keys and root keys
	sendingChainKey, receivingChainKey, nextSendingRootKey, nextReceivingRootKey, err := performDHAndDeriveKeys(s.DHRatchetPrivKey[:], remoteDHPubKey, s.SendingRootKey, s.ReceivingRootKey)
	if err != nil {
		return err
	}

	// Update ratchet state with new keys
	s.updateRatchetChains(sendingChainKey, receivingChainKey, nextSendingRootKey, nextReceivingRootKey, remoteDHPubKey)

	// Generate a new ephemeral key pair for the next ratchet step
	if err := s.initializeDHRatchet(); err != nil {
		return oops.Errorf("failed to generate new DH ratchet key: %w", err)
	}

	// Update tag ratchets with new chain keys
	updateSessionTagRatchets(s)

	log.WithFields(logger.Fields{"pkg": "ecies", "func": "SessionState.PerformDHRatchet", "remote_dh_key": remoteDHPubKey[:8]}).Debug("DH ratchet performed")
	return nil
}

// performDHAndDeriveKeys performs Diffie-Hellman key agreement and derives the
// new chain keys and root keys for both directions, per I2P Proposal 144 §4:
//
//	tagsetKey = HKDF(sharedSecret, ZEROLEN, "XDHRatchetTagSet", 32)
//	newTagSet = DH_INITIALIZE(rootKey, tagsetKey)   // per direction
//
// It returns the new sending/receiving chain keys and the next root keys for
// each direction.
func performDHAndDeriveKeys(localPrivKey, remotePubKey []byte, sendingRootKey, receivingRootKey [32]byte) (sendingChainKey, receivingChainKey, nextSendingRootKey, nextReceivingRootKey [32]byte, err error) {
	// Perform DH with remote's new public key
	sharedSecret, err := performDH(localPrivKey, remotePubKey)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{}, oops.Errorf("DH ratchet key agreement failed: %w", err)
	}

	// tagsetKey = HKDF(sharedSecret, ZEROLEN, "XDHRatchetTagSet", 32)
	tagsetKey, err := kdf.StandardHKDF(sharedSecret, nil, []byte("XDHRatchetTagSet"), 32)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{}, oops.Errorf("DH ratchet tagset key derivation failed: %w", err)
	}
	var tagsetKeyArray [32]byte
	copy(tagsetKeyArray[:], tagsetKey)

	// newTagSet = DH_INITIALIZE(rootKey, tagsetKey), per direction
	nextSendingRootKey, sendingChainKey, err = ratchet.DH_INITIALIZEFull(sendingRootKey, tagsetKeyArray)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{}, oops.Errorf("DH ratchet sending tagset initialization failed: %w", err)
	}

	nextReceivingRootKey, receivingChainKey, err = ratchet.DH_INITIALIZEFull(receivingRootKey, tagsetKeyArray)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{}, oops.Errorf("DH ratchet receiving tagset initialization failed: %w", err)
	}

	return sendingChainKey, receivingChainKey, nextSendingRootKey, nextReceivingRootKey, nil
}

// updateRatchetChains updates the sending and receiving chain keys and root keys
// after a DH ratchet. Resets message counters and stores the remote DH public key.
func (s *SessionState) updateRatchetChains(sendingChainKey, receivingChainKey, nextSendingRootKey, nextReceivingRootKey [32]byte, remoteDHPubKey []byte) {
	// Update receiving chain (we receive with new remote DH key)
	s.ReceivingChainKey = receivingChainKey
	s.ReceivingRootKey = nextReceivingRootKey
	s.PreviousChainLength = s.SendingMessageNum
	s.ReceivingMessageNum = 0

	// Update sending chain (we send with our existing DH key)
	s.SendingChainKey = sendingChainKey
	s.SendingRootKey = nextSendingRootKey
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

	log.WithFields(logger.Fields{"pkg": "ecies", "func": "SessionState.GetNextSendingTag", "tag": tag[:]}).Debug("Generated sending tag")
	return tag, nil
}

// ValidateReceivingTag checks if a received tag matches any tag in the
// receiving lookahead window (spec §4: the receiver may be up to N tags ahead,
// N ≤ 128, 32 recommended). On a match the receiving tag ratchet is advanced
// to the matched position and the window is rebuilt.
func (s *SessionState) ValidateReceivingTag(tag [8]byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.receivingLookaheadTags) == 0 {
		s.rebuildReceivingLookahead()
	}

	for i, expected := range s.receivingLookaheadTags {
		if constantTimeEqual(tag[:], expected[:]) {
			// Advance the ratchet to the matched position.
			for j := 0; j <= i; j++ {
				if _, err := s.ReceivingTagRatchet.GenerateNextTag(); err != nil {
					return false, err
				}
			}
			s.rebuildReceivingLookahead()
			return true, nil
		}
	}

	return false, nil
}

// rebuildReceivingLookahead rebuilds the receiving lookahead window by walking
// a copy of the receiving tag ratchet. The window size is clamped to
// [DefaultLookaheadWindow, MaxLookaheadWindow].
func (s *SessionState) rebuildReceivingLookahead() {
	probe := *s.ReceivingTagRatchet
	tags := make([][ratchet.SessionTagSize]byte, 0, ratchet.DefaultLookaheadWindow)
	for i := 0; i < ratchet.DefaultLookaheadWindow; i++ {
		tag, err := probe.PeekNextTag()
		if err != nil {
			break
		}
		tags = append(tags, tag)
		probe.Advance()
	}
	s.receivingLookaheadTags = tags
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
	zeroBytes(s.SendingRootKey[:])
	zeroBytes(s.ReceivingRootKey[:])

	if s.SendingTagRatchet != nil {
		s.SendingTagRatchet.Zero()
	}
	if s.ReceivingTagRatchet != nil {
		s.ReceivingTagRatchet.Zero()
	}

	for i := range s.receivingLookaheadTags {
		zeroBytes(s.receivingLookaheadTags[i][:])
	}
	s.receivingLookaheadTags = nil
}

// Helper function to zero a byte slice securely
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
