package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type (
	// RSA2048PublicKey represents a 2048-bit RSA public key in I2P format.
	// The key is stored as a 256-byte array containing the public key modulus.
	// This type implements types.Verifier for signature verification operations.
	//
	// ⚠️ CRITICAL SECURITY WARNING ⚠️
	// Always use NewRSA2048PublicKey() to create instances.
	// Do NOT construct directly with &RSA2048PublicKey{} or RSA2048PublicKey{}.
	//
	// Example usage:
	//
	//	// WRONG - Creates invalid zero-value key
	//	var key RSA2048PublicKey
	//
	//	// CORRECT - Validates key data
	//	key, err := NewRSA2048PublicKey(keyBytes)
	RSA2048PublicKey [256]byte
)

// NewRSA2048PublicKey creates a validated RSA-2048 public key from bytes.
//
// The input data must be exactly 256 bytes containing the modulus (N)
// in big-endian format as per I2P specifications.
//
// Returns an error if:
//   - data length is not exactly 256 bytes
//   - data is all zeros (cryptographically invalid)
//
// The returned key is a defensive copy - modifications to the input
// slice will not affect the key.
func NewRSA2048PublicKey(data []byte) (*RSA2048PublicKey, error) {
	if len(data) != 256 {
		return nil, oops.Errorf("RSA-2048 public key must be 256 bytes, got %d: %w", len(data), ErrInvalidKeySize)
	}

	// Check for all-zero key (cryptographically invalid)
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, oops.Errorf("RSA-2048 public key cannot be all zeros: %w", ErrInvalidKeyFormat)
	}

	// Create defensive copy
	var key RSA2048PublicKey
	copy(key[:], data)

	log.Debug("RSA-2048 public key created successfully")
	return &key, nil
}

// Verify implements types.Verifier.
// This method hashes the data with SHA-256 and verifies the signature
func (r RSA2048PublicKey) Verify(data []byte, sig []byte) error {
	// Hash the data with SHA-256 (appropriate for RSA-2048)
	hash := sha256.Sum256(data)
	return r.VerifyHash(hash[:], sig)
}

// VerifyHash implements types.Verifier.
// This method verifies a pre-computed hash against the signature
func (r RSA2048PublicKey) VerifyHash(h []byte, sig []byte) error {
	// Convert I2P byte format to standard RSA public key structure
	pubKey, err := rsaPublicKeyFromBytes(r[:], 256)
	if err != nil {
		return oops.Errorf("failed to parse RSA2048 public key: %w", err)
	}

	// For RSA2048, we use SHA-256 hash algorithm as per I2P specifications
	if len(h) != sha256.Size {
		return oops.Errorf("RSA2048 verification requires SHA-256 hash (expected %d bytes, got %d)",
			sha256.Size, len(h))
	}

	// Perform PKCS#1 v1.5 signature verification using Go's crypto/rsa
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h, sig)
	if err != nil {
		return oops.Errorf("RSA signature verification failed: %w", err)
	}

	return nil
}

// Bytes implements SigningPublicKey.
// Returns the raw bytes of the public key
func (r RSA2048PublicKey) Bytes() []byte {
	return r[:]
}

// Len implements SigningPublicKey.
// Returns the length of the public key in bytes
func (r RSA2048PublicKey) Len() int {
	return len(r)
}

// NewVerifier implements SigningPublicKey.
// Creates a new verifier object that can be used to verify signatures
func (r RSA2048PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new RSA-2048 verifier")
	return r, nil
}

var (
	_ types.PublicKey = RSA2048PublicKey{}
	_ types.Verifier  = RSA2048PublicKey{}
)
