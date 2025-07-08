package hkdf

import (
	"crypto/sha256"
	"io"

	"github.com/samber/oops"
	"golang.org/x/crypto/hkdf"
)

// Derive derives a key of the specified length from the input key material (IKM)
func (h *HKDFImpl) Derive(ikm, salt, info []byte, keyLen int) ([]byte, error) {
	log.WithField("ikm_length", len(ikm)).
		WithField("salt_length", len(salt)).
		WithField("info_length", len(info)).
		WithField("key_length", keyLen).
		Debug("Deriving key with HKDF")

	// Validate inputs
	if keyLen <= 0 {
		return nil, oops.Wrapf(ErrInvalidKeyLength, "key length must be positive, got %d", keyLen)
	}

	if len(info) > MaxInfoLength {
		return nil, oops.Wrapf(ErrInvalidInfoLength, "info length exceeds maximum %d bytes", MaxInfoLength)
	}

	// Get hash function
	hashFunc := h.hashFunc
	if hashFunc == nil {
		hashFunc = sha256.New
	}

	// Create HKDF reader
	reader := hkdf.New(hashFunc, ikm, salt, info)

	// Derive key
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, oops.Wrapf(ErrKeyDerivationFailed, "failed to derive key: %w", err)
	}

	log.WithField("derived_key_length", len(key)).Debug("HKDF key derivation successful")
	return key, nil
}

// DeriveDefault derives a key using default parameters (32 bytes, no salt, no info)
func (h *HKDFImpl) DeriveDefault(ikm []byte) ([]byte, error) {
	return h.Derive(ikm, nil, nil, DefaultKeyLength)
}
