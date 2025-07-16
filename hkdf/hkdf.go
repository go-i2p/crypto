package hkdf

import (
	"crypto/sha256"
	"io"

	"github.com/samber/oops"
	"golang.org/x/crypto/hkdf"
)

// Derive implements types.KeyDeriver for HKDF key derivation operations.
// Derives a cryptographic key of specified length from input key material using RFC 5869 HKDF.
// Parameters: ikm (input key material), salt (optional random value), info (context data), keyLen (output length).
// Returns derived key bytes or error if derivation fails due to invalid parameters.
// Derive derives a key of the specified length from the input key material (IKM)
func (h *HKDFImpl) Derive(ikm, salt, info []byte, keyLen int) ([]byte, error) {
	log.WithField("ikm_length", len(ikm)).
		WithField("salt_length", len(salt)).
		WithField("info_length", len(info)).
		WithField("key_length", keyLen).
		Debug("Deriving key with HKDF")

	// Validate key length parameter for security and compatibility
	if keyLen <= 0 {
		return nil, oops.Wrapf(ErrInvalidKeyLength, "key length must be positive, got %d", keyLen)
	}

	// Enforce RFC 5869 info length limit to prevent security issues
	if len(info) > MaxInfoLength {
		return nil, oops.Wrapf(ErrInvalidInfoLength, "info length exceeds maximum %d bytes", MaxInfoLength)
	}

	// Select hash function with secure default fallback to SHA-256
	// Get hash function
	hashFunc := h.hashFunc
	if hashFunc == nil {
		hashFunc = sha256.New
	}

	// Initialize HKDF reader using validated parameters and selected hash function
	// Create HKDF reader
	reader := hkdf.New(hashFunc, ikm, salt, info)

	// Perform key derivation with proper error handling for cryptographic failures
	// Derive key
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, oops.Wrapf(ErrKeyDerivationFailed, "failed to derive key: %w", err)
	}

	log.WithField("derived_key_length", len(key)).Debug("HKDF key derivation successful")
	return key, nil
}

// DeriveDefault provides convenient HKDF key derivation with I2P standard parameters.
// Derives a 32-byte key from input key material using no salt and no contextual info.
// Optimized for I2P applications requiring ChaCha20-compatible 256-bit keys.
// DeriveDefault derives a key using default parameters (32 bytes, no salt, no info)
func (h *HKDFImpl) DeriveDefault(ikm []byte) ([]byte, error) {
	return h.Derive(ikm, nil, nil, DefaultKeyLength)
}
