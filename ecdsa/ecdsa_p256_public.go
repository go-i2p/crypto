package ecdsa

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type (
	// ECP256PublicKey represents a P-256 ECDSA public key in uncompressed form.
	//
	// CRITICAL: Never create ECP256PublicKey using zero-value construction (e.g. var key ECP256PublicKey).
	// Zero-value construction results in an invalid public key which:
	//   - Will fail signature verification
	//   - May panic in cryptographic operations
	//   - Violates ECDSA security requirements
	//
	// ALWAYS use NewECP256PublicKey() for safe construction.
	ECP256PublicKey [64]byte
)

// NewECP256PublicKey creates a new P-256 ECDSA public key from bytes with validation.
//
// This constructor provides mandatory validation to prevent common security issues:
//   - Rejects inputs that are not exactly 64 bytes (uncompressed X||Y point)
//   - Returns defensive copy to prevent external mutation
//
// Note: This constructor validates size only. Full curve point validation occurs
// when the key is used for cryptographic operations.
//
// Returns an error if:
//   - Input is not exactly 64 bytes
func NewECP256PublicKey(data []byte) (*ECP256PublicKey, error) {
	if len(data) != 64 {
		return nil, oops.Errorf("invalid P-256 public key size: expected 64 bytes (uncompressed point), got %d bytes", len(data))
	}

	var key ECP256PublicKey
	copy(key[:], data)
	return &key, nil
}

// Verify implements types.Verifier.
func (k ECP256PublicKey) Verify(data, sig []byte) error {
	log.WithField("data_length", len(data)).Debug("Verifying data with ECDSA-P256")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.Verify(data, sig)
}

// VerifyHash implements types.Verifier.
func (k ECP256PublicKey) VerifyHash(h, sig []byte) error {
	log.WithField("hash_length", len(h)).Debug("Verifying hash with ECDSA-P256")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.VerifyHash(h, sig)
}

// Encrypt implements types.Encrypter.
func (k *ECP256PublicKey) Encrypt(data []byte) (enc []byte, err error) {
	log.Error("Encryption not supported with ECDSA keys")
	return nil, oops.Errorf("encryption not supported with ECDSA keys; ECDSA is for signing/verification only")
}

func (k ECP256PublicKey) Len() int {
	return len(k)
}

func (k ECP256PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP256PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new P256 ECDSA verifier")
	// return createECVerifier(elliptic.P256(), crypto.SHA256, k[:])
	v, err := CreateECVerifier(elliptic.P256(), crypto.SHA256, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P256 ECDSA verifier")
	}
	return v, err
}

var _ types.Verifier = ECP256PublicKey{}
