package ecdsa

import (
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type (
	// ECP384PrivateKey represents a P-384 ECDSA private key.
	//
	// CRITICAL: Never create ECP384PrivateKey using zero-value construction (e.g. var key ECP384PrivateKey).
	// Zero-value construction results in an all-zero key which:
	//   - Is cryptographically invalid
	//   - Will panic when calling Public()
	//   - Violates ECDSA security requirements
	//
	// ALWAYS use NewECP384PrivateKey() for safe construction.
	ECP384PrivateKey [48]byte
)

// NewECP384PrivateKey creates a new P-384 ECDSA private key from bytes with validation.
//
// This constructor provides mandatory validation to prevent common security issues:
//   - Rejects inputs that are not exactly 48 bytes
//   - Rejects all-zero keys (cryptographically invalid)
//   - Returns defensive copy to prevent external mutation
//
// Use this instead of direct byte slice conversion to ensure key validity.
//
// Returns an error if:
//   - Input is not exactly 48 bytes
//   - Input is all zeros (invalid ECDSA private key)
func NewECP384PrivateKey(data []byte) (*ECP384PrivateKey, error) {
	if len(data) != 48 {
		return nil, oops.Errorf("invalid P-384 private key size: expected 48 bytes, got %d bytes", len(data))
	}

	// Check for all-zero key (cryptographically invalid)
	isZero := true
	for _, b := range data {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return nil, oops.Errorf("invalid P-384 private key: cannot be all zeros")
	}

	var key ECP384PrivateKey
	copy(key[:], data)
	return &key, nil
}

// Sign implements types.Signer.
func (e *ECP384PrivateKey) Sign(data []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// SignHash implements types.Signer.
func (e *ECP384PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// Decrypt implements types.Decrypter.
func (e *ECP384PrivateKey) Decrypt(data []byte) ([]byte, error) {
	panic("unimplemented")
}

// Bytes implements types.PrivateKey.
func (e *ECP384PrivateKey) Bytes() []byte {
	panic("unimplemented")
}

// Public implements types.PrivateKey.
func (e *ECP384PrivateKey) Public() (types.SigningPublicKey, error) {
	panic("unimplemented")
}

// Zero implements types.PrivateKey.
func (e *ECP384PrivateKey) Zero() {
	panic("unimplemented")
}
