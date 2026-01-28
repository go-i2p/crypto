package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type (
	// RSA4096PublicKey represents a 4096-bit RSA public key in I2P format.
	// The key is stored as a 512-byte array containing the public key modulus.
	// This type implements types.Verifier for signature verification with maximum security.
	// RSA-4096 provides equivalent security to 192-bit symmetric encryption.
	//
	// ⚠️ CRITICAL SECURITY WARNING ⚠️
	// Always use NewRSA4096PublicKey() to create instances.
	// Do NOT construct directly with &RSA4096PublicKey{} or RSA4096PublicKey{}.
	RSA4096PublicKey [512]byte
)

// NewRSA4096PublicKey creates a validated RSA-4096 public key from bytes.
//
// The input data must be exactly 512 bytes containing the modulus (N)
// in big-endian format as per I2P specifications.
//
// Returns an error if:
//   - data length is not exactly 512 bytes
//   - data is all zeros (cryptographically invalid)
//
// The returned key is a defensive copy - modifications to the input
// slice will not affect the key.
func NewRSA4096PublicKey(data []byte) (*RSA4096PublicKey, error) {
	if len(data) != 512 {
		return nil, oops.Errorf("RSA-4096 public key must be 512 bytes, got %d: %w", len(data), ErrInvalidKeySize)
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
		return nil, oops.Errorf("RSA-4096 public key cannot be all zeros: %w", ErrInvalidKeyFormat)
	}

	// Create defensive copy
	var key RSA4096PublicKey
	copy(key[:], data)

	log.Debug("RSA-4096 public key created successfully")
	return &key, nil
}

// Verify implements types.Verifier.
// This method hashes the data with SHA-512 and verifies the signature
func (r RSA4096PublicKey) Verify(data, sig []byte) error {
	log.Debug("Verifying RSA-4096 signature")
	// Hash the data with SHA-512 (appropriate for RSA-4096)
	hash := sha512.Sum512(data)
	return r.VerifyHash(hash[:], sig)
}

// VerifyHash implements types.Verifier.
// This method verifies a pre-computed hash against the signature
func (r RSA4096PublicKey) VerifyHash(h, sig []byte) error {
	log.Debug("Verifying RSA-4096 signature with pre-computed hash")
	// Convert I2P byte format to standard RSA public key structure
	pubKey, err := rsaPublicKeyFromBytes(r[:], 512)
	if err != nil {
		log.WithError(err).Error("Failed to parse RSA-4096 public key")
		return oops.Errorf("invalid RSA-4096 public key: %w", err)
	}

	// For RSA4096, we use SHA-512 for maximum security as per I2P specifications
	if len(h) != sha512.Size {
		return oops.Errorf("RSA4096 verification requires SHA-512 hash (expected %d bytes, got %d)",
			sha512.Size, len(h))
	}

	// Verify the signature using PKCS1v15 with SHA-512 for highest security level
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, h, sig)
	if err != nil {
		return oops.Errorf("RSA signature verification failed: %w", err)
	}

	log.Debug("RSA-4096 signature verified successfully")
	return nil
}

// Bytes implements SigningPublicKey.
// Returns the raw bytes of the public key
func (r RSA4096PublicKey) Bytes() []byte {
	return r[:]
}

// Len implements SigningPublicKey.
// Returns the length of the public key in bytes
func (r RSA4096PublicKey) Len() int {
	return len(r)
}

// NewVerifier implements SigningPublicKey.
// Creates a new verifier instance for this public key
func (r RSA4096PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new RSA-4096 verifier")
	return r, nil
}

var (
	_ types.PublicKey = RSA4096PublicKey{}
	_ types.Verifier  = RSA4096PublicKey{}
)
