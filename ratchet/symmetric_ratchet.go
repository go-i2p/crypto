// Package ratchet symmetric key ratchet implementation.
package ratchet

import (
	"encoding/binary"

	"github.com/go-i2p/crypto/hmac"
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

// DeriveMessageKey derives a message encryption key for the given message number.
// Uses HMAC-SHA256(chainKey, "MessageKey" || messageNum).
func (r *SymmetricRatchet) DeriveMessageKey(messageNum uint32) ([MessageKeySize]byte, error) {
	// Prepare input: "MessageKey" || messageNum
	input := make([]byte, len("MessageKey")+4)
	copy(input, []byte("MessageKey"))
	binary.BigEndian.PutUint32(input[len("MessageKey"):], messageNum)

	// Compute HMAC using our existing hmac package
	var hmacKey hmac.HMACKey
	copy(hmacKey[:], r.chainKey[:])
	digest := hmac.I2PHMAC(input, hmacKey)

	// Use full 32 bytes for message key
	var messageKey [MessageKeySize]byte
	copy(messageKey[:], digest[:MessageKeySize])

	return messageKey, nil
}

// Advance advances the symmetric ratchet by deriving a new chain key.
// Uses HMAC-SHA256(chainKey, "NextChainKey").
func (r *SymmetricRatchet) Advance() error {
	// Prepare input: "NextChainKey"
	input := []byte("NextChainKey")

	// Compute HMAC using our existing hmac package
	var hmacKey hmac.HMACKey
	copy(hmacKey[:], r.chainKey[:])
	digest := hmac.I2PHMAC(input, hmacKey)

	// Update chain key
	copy(r.chainKey[:], digest[:ChainKeySize])

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
