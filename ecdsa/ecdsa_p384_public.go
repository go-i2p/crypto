package ecdsa

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type (
	// ECP384PublicKey represents a P-384 ECDSA public key in uncompressed form.
	//
	// CRITICAL: Never create ECP384PublicKey using zero-value construction (e.g. var key ECP384PublicKey).
	// Zero-value construction results in an invalid public key which:
	//   - Will fail signature verification
	//   - May panic in cryptographic operations
	//   - Violates ECDSA security requirements
	//
	// ALWAYS use NewECP384PublicKey() for safe construction.
	ECP384PublicKey [96]byte
)

// NewECP384PublicKey creates a new P-384 ECDSA public key from bytes with validation.
//
// This constructor provides mandatory validation to prevent common security issues:
//   - Rejects inputs that are not exactly 96 bytes (uncompressed X||Y point)
//   - Returns defensive copy to prevent external mutation
//
// Note: This constructor validates size only. Full curve point validation occurs
// when the key is used for cryptographic operations.
//
// Returns an error if:
//   - Input is not exactly 96 bytes
func NewECP384PublicKey(data []byte) (*ECP384PublicKey, error) {
	if len(data) != 96 {
		return nil, oops.Errorf("invalid P-384 public key size: expected 96 bytes (uncompressed point), got %d bytes", len(data))
	}

	var key ECP384PublicKey
	copy(key[:], data)
	return &key, nil
}

// Verify implements types.Verifier.
func (k ECP384PublicKey) Verify(data []byte, sig []byte) error {
	log.WithField("data_length", len(data)).Debug("Verifying data with ECDSA-P384")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.Verify(data, sig)
}

// VerifyHash implements types.Verifier.
func (k ECP384PublicKey) VerifyHash(h []byte, sig []byte) error {
	log.WithField("hash_length", len(h)).Debug("Verifying hash with ECDSA-P384")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.VerifyHash(h, sig)
}

func (k ECP384PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP384PublicKey) Len() int {
	return len(k)
}

func (k ECP384PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new P384 ECDSA verifier")
	v, err := CreateECVerifier(elliptic.P384(), crypto.SHA384, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P384 ECDSA verifier")
	}
	return v, err
	// return createECVerifier(elliptic.P384(), crypto.SHA384, k[:])
}

var _ types.Verifier = ECP384PublicKey{}
