package ecdsa

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type (
	// ECP521PublicKey represents a P-521 ECDSA public key in uncompressed form.
	//
	// CRITICAL: Never create ECP521PublicKey using zero-value construction (e.g. var key ECP521PublicKey).
	// Zero-value construction results in an invalid public key which:
	//   - Will fail signature verification
	//   - May panic in cryptographic operations
	//   - Violates ECDSA security requirements
	//
	// ALWAYS use NewECP521PublicKey() for safe construction.
	ECP521PublicKey [132]byte
)

// NewECP521PublicKey creates a new P-521 ECDSA public key from bytes with validation.
//
// This constructor provides mandatory validation to prevent common security issues:
//   - Rejects inputs that are not exactly 132 bytes (uncompressed X||Y point)
//   - Returns defensive copy to prevent external mutation
//
// Note: This constructor validates size only. Full curve point validation occurs
// when the key is used for cryptographic operations.
//
// Returns an error if:
//   - Input is not exactly 132 bytes
func NewECP521PublicKey(data []byte) (*ECP521PublicKey, error) {
	if len(data) != 132 {
		return nil, oops.Errorf("invalid P-521 public key size: expected 132 bytes (uncompressed point), got %d bytes", len(data))
	}

	var key ECP521PublicKey
	copy(key[:], data)
	return &key, nil
}

// Verify implements types.Verifier.
func (k ECP521PublicKey) Verify(data, sig []byte) error {
	log.WithField("data_length", len(data)).Debug("Verifying data with ECDSA-P521")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.Verify(data, sig)
}

// VerifyHash implements types.Verifier.
func (k ECP521PublicKey) VerifyHash(h, sig []byte) error {
	log.WithField("hash_length", len(h)).Debug("Verifying hash with ECDSA-P521")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.VerifyHash(h, sig)
}

func (k ECP521PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP521PublicKey) Len() int {
	return len(k)
}

func (k ECP521PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new P521 ECDSA verifier")
	v, err := CreateECVerifier(elliptic.P521(), crypto.SHA512, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P521 ECDSA verifier")
	}
	return v, err
	// return createECVerifier(elliptic.P521(), crypto.SHA512, k[:])
}
