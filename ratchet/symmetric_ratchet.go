// Package ratchet symmetric key ratchet implementation.
package ratchet

import (
	"encoding/binary"

	"github.com/go-i2p/crypto/kdf"
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

func (r *SymmetricRatchet) DeriveMessageKey(messageNum uint32) ([MessageKeySize]byte, error) {
	// Derive a message key from the current chain key and the message index so that
	// different message numbers produce different keys while identical message numbers
	// remain deterministic.
	info := make([]byte, 0, len("SymmetricRatchet")+4)
	info = append(info, []byte("SymmetricRatchet")...)
	var msgNum [4]byte
	binary.BigEndian.PutUint32(msgNum[:], messageNum)
	info = append(info, msgNum[:]...)

	kd := kdf.NewKeyDerivation(r.chainKey)
	keys, err := kd.DeriveKeys(info, 2)
	if err != nil {
		return [MessageKeySize]byte{}, err
	}
	var messageKey [MessageKeySize]byte
	copy(messageKey[:], keys[1][:])
	return messageKey, nil
}

// Advance advances the symmetric ratchet by deriving a new chain key.
// Uses HMAC-SHA256(chainKey, "NextChainKey").
func (r *SymmetricRatchet) Advance() error {
	kd := kdf.NewKeyDerivation(r.chainKey)
	keys, err := kd.DeriveKeys([]byte("NextChainKey"), 1)
	if err != nil {
		return err
	}
	copy(r.chainKey[:], keys[0][:])
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
