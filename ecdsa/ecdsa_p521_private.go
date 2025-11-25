package ecdsa

import (
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type (
	// ECP521PrivateKey represents a P-521 ECDSA private key.
	//
	// CRITICAL: Never create ECP521PrivateKey using zero-value construction (e.g. var key ECP521PrivateKey).
	// Zero-value construction results in an all-zero key which:
	//   - Is cryptographically invalid
	//   - Will panic when calling Public()
	//   - Violates ECDSA security requirements
	//
	// ALWAYS use NewECP521PrivateKey() for safe construction.
	ECP521PrivateKey [66]byte
)

// NewECP521PrivateKey creates a new P-521 ECDSA private key from bytes with validation.
//
// This constructor provides mandatory validation to prevent common security issues:
//   - Rejects inputs that are not exactly 66 bytes
//   - Rejects all-zero keys (cryptographically invalid)
//   - Returns defensive copy to prevent external mutation
//
// Use this instead of direct byte slice conversion to ensure key validity.
//
// Returns an error if:
//   - Input is not exactly 66 bytes
//   - Input is all zeros (invalid ECDSA private key)
func NewECP521PrivateKey(data []byte) (*ECP521PrivateKey, error) {
	if len(data) != 66 {
		return nil, oops.Errorf("invalid P-521 private key size: expected 66 bytes, got %d bytes", len(data))
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
		return nil, oops.Errorf("invalid P-521 private key: cannot be all zeros")
	}

	var key ECP521PrivateKey
	copy(key[:], data)
	return &key, nil
}

// Sign implements types.Signer.
func (e *ECP521PrivateKey) Sign(data []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// SignHash implements types.Signer.
func (e *ECP521PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// Decrypt implements types.Decrypter.
func (e *ECP521PrivateKey) Decrypt(data []byte) ([]byte, error) {
	panic("unimplemented")
}

// Bytes implements types.PrivateKey.
func (e *ECP521PrivateKey) Bytes() []byte {
	panic("unimplemented")
}

// Public implements types.PrivateKey.
func (e *ECP521PrivateKey) Public() (types.SigningPublicKey, error) {
	panic("unimplemented")
}

// Zero implements types.PrivateKey.
func (e *ECP521PrivateKey) Zero() {
	panic("unimplemented")
}
