package ratchet

import (
	"github.com/go-i2p/crypto/hkdf"
)

// SymmetricRatchet implements the symmetric key ratchet for deriving message keys.
// Each message is encrypted with a unique key derived from the chain key.
//
// The ratchet provides forward secrecy - message keys cannot be derived from
// later chain keys, and compromise of one message key doesn't affect others.
//
// ⚠️ CRITICAL SECURITY WARNING:
// Do NOT construct SymmetricRatchet directly using var or struct literals.
// Always use NewSymmetricRatchet() to ensure proper initialization.
//
// BAD:
//
//	var ratchet SymmetricRatchet       // Zero chain key - cryptographically invalid!
//	ratchet := SymmetricRatchet{...}   // Missing validation
//
// GOOD:
//
//	ratchet := NewSymmetricRatchet(initialChainKey)
type SymmetricRatchet struct {
	chainKey [ChainKeySize]byte
}

// NewSymmetricRatchet creates a new symmetric key ratchet.
func NewSymmetricRatchet(initialChainKey [ChainKeySize]byte) *SymmetricRatchet {
	return &SymmetricRatchet{
		chainKey: initialChainKey,
	}
}

// deriveKeydata runs the spec's SymmetricRatchet KDF (section 4c):
//
//	keydata = HKDF(ikm=ZEROLEN, salt=chainKey, info="SymmetricRatchet", 64)
//
// The first 32 bytes are the next chain key and the last 32 bytes are the
// message key.
func (r *SymmetricRatchet) deriveKeydata() ([]byte, error) {
	return hkdf.NewHKDF().Derive(nil, r.chainKey[:], []byte("SymmetricRatchet"), 64)
}

// DeriveMessageKey derives the message key for the current chain key.
// Per the I2P ECIES spec (section 4c), the message key is the second half of
// keydata = HKDF(ikm=ZEROLEN, salt=chainKey, info="SymmetricRatchet", 64).
// The message number is not part of the KDF; it is accepted for API
// compatibility with existing callers.
func (r *SymmetricRatchet) DeriveMessageKey(messageNum uint32) ([MessageKeySize]byte, error) {
	keydata, err := r.deriveKeydata()
	if err != nil {
		return [MessageKeySize]byte{}, err
	}
	var messageKey [MessageKeySize]byte
	copy(messageKey[:], keydata[32:64])
	return messageKey, nil
}

// Advance advances the symmetric ratchet by deriving a new chain key.
// Per the I2P ECIES spec (section 4c), the new chain key is the first half of
// keydata = HKDF(ikm=ZEROLEN, salt=chainKey, info="SymmetricRatchet", 64).
func (r *SymmetricRatchet) Advance() error {
	keydata, err := r.deriveKeydata()
	if err != nil {
		return err
	}
	copy(r.chainKey[:], keydata[0:32])
	return nil
}

// GetChainKey returns the current chain key (for inspection/debugging).
func (r *SymmetricRatchet) GetChainKey() [ChainKeySize]byte {
	return r.chainKey
}

// Zero securely clears the symmetric ratchet state from memory.
func (r *SymmetricRatchet) Zero() {
	for i := range r.chainKey {
		r.chainKey[i] = 0
	}
}

// DeriveMessageKeyAndAdvance derives a message key and advances the chain in one operation.
// This is a convenience function combining DeriveMessageKey and Advance.
func (r *SymmetricRatchet) DeriveMessageKeyAndAdvance(messageNum uint32) ([MessageKeySize]byte, [ChainKeySize]byte, error) {
	// Derive message key
	messageKey, err := r.DeriveMessageKey(messageNum)
	if err != nil {
		return [MessageKeySize]byte{}, [ChainKeySize]byte{}, err
	}

	// Get current chain key before advancing
	oldChainKey := r.chainKey

	// Advance to next chain key
	if err := r.Advance(); err != nil {
		return [MessageKeySize]byte{}, [ChainKeySize]byte{}, err
	}

	return messageKey, oldChainKey, nil
}
