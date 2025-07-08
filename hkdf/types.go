package hkdf

import (
	"hash"
)

// HKDF interface for key derivation function
type HKDF interface {
	// Derive derives a key of the specified length from the input key material (IKM)
	// salt: optional salt value (can be nil)
	// info: optional context and application-specific information (can be nil)
	// keyLen: desired length of the derived key in bytes
	Derive(ikm, salt, info []byte, keyLen int) ([]byte, error)

	// DeriveDefault derives a key using default parameters (32 bytes, no salt, no info)
	DeriveDefault(ikm []byte) ([]byte, error)
}

// HKDFImpl is the concrete implementation of HKDF using SHA-256
type HKDFImpl struct {
	hashFunc func() hash.Hash
}

// NewHKDF creates a new HKDF instance with SHA-256
func NewHKDF() HKDF {
	return &HKDFImpl{
		hashFunc: nil, // Will default to SHA-256 in implementation
	}
}

// NewHKDFWithHash creates a new HKDF instance with custom hash function
func NewHKDFWithHash(hashFunc func() hash.Hash) HKDF {
	return &HKDFImpl{
		hashFunc: hashFunc,
	}
}
