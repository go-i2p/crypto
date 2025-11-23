package hkdf

import (
	"crypto/sha256"
	"hash"
	"io"

	"github.com/samber/oops"
	"golang.org/x/crypto/hkdf"
)

// Derive derives a key of the specified length from the input key material (IKM).
// Parameters: ikm (input key material), salt (optional random value), info (context data), keyLen (output length).
// Returns derived key bytes or error if derivation fails due to invalid parameters.
func (h *HKDFImpl) Derive(ikm, salt, info []byte, keyLen int) ([]byte, error) {
	log.WithField("ikm_length", len(ikm)).
		WithField("salt_length", len(salt)).
		WithField("info_length", len(info)).
		WithField("key_length", keyLen).
		Debug("Deriving key with HKDF")

	// Validate input parameters
	if err := validateDeriveParameters(keyLen, info); err != nil {
		return nil, err
	}

	// Select hash function with secure default fallback to SHA-256
	hashFunc := selectHashFunction(h.hashFunc)

	// Initialize HKDF reader and derive key
	key, err := performKeyDerivation(hashFunc, ikm, salt, info, keyLen)
	if err != nil {
		return nil, err
	}

	log.WithField("derived_key_length", len(key)).Debug("HKDF key derivation successful")
	return key, nil
}

// validateDeriveParameters checks that key length and info length meet security requirements.
func validateDeriveParameters(keyLen int, info []byte) error {
	if keyLen <= 0 {
		return oops.Wrapf(ErrInvalidKeyLength, "key length must be positive, got %d", keyLen)
	}

	// Enforce RFC 5869 info length limit to prevent security issues
	if len(info) > MaxInfoLength {
		return oops.Wrapf(ErrInvalidInfoLength, "info length exceeds maximum %d bytes", MaxInfoLength)
	}

	return nil
}

// selectHashFunction returns the configured hash function or SHA-256 as secure default.
func selectHashFunction(hashFunc func() hash.Hash) func() hash.Hash {
	if hashFunc == nil {
		return sha256.New
	}
	return hashFunc
}

// performKeyDerivation executes the HKDF key derivation process.
// Creates an HKDF reader and derives the requested number of key bytes.
func performKeyDerivation(hashFunc func() hash.Hash, ikm, salt, info []byte, keyLen int) ([]byte, error) {
	// Create HKDF reader
	reader := hkdf.New(hashFunc, ikm, salt, info)

	// Derive key
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, oops.Wrapf(ErrKeyDerivationFailed, "failed to derive key: %w", err)
	}

	return key, nil
}

// DeriveDefault provides convenient HKDF key derivation with I2P standard parameters.
// Derives a 32-byte key from input key material using no salt and no contextual info.
// Optimized for I2P applications requiring ChaCha20-compatible 256-bit keys.
// DeriveDefault derives a key using default parameters (32 bytes, no salt, no info)
func (h *HKDFImpl) DeriveDefault(ikm []byte) ([]byte, error) {
	return h.Derive(ikm, nil, nil, DefaultKeyLength)
}
