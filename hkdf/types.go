package hkdf

import (
	"hash"

	"github.com/go-i2p/crypto/types"
)

// HKDFKey provides a standard entry point for HKDF key derivation
type HKDFKey struct{}

// NewDeriver returns a types.KeyDeriver for HKDF
func (k HKDFKey) NewDeriver() types.KeyDeriver {
	return NewHKDF()
}

// HKDFImpl is the concrete implementation of HKDF using SHA-256
type HKDFImpl struct {
	hashFunc func() hash.Hash
}

// NewHKDF creates a new HKDF instance with SHA-256

// NewHKDF returns a types.KeyDeriver for HKDF using SHA-256
func NewHKDF() types.KeyDeriver {
	return &HKDFImpl{
		hashFunc: nil, // Will default to SHA-256 in implementation
	}
}

// NewHKDFWithHash creates a new HKDF instance with custom hash function

// NewHKDFWithHash returns a types.KeyDeriver for HKDF using a custom hash function
func NewHKDFWithHash(hashFunc func() hash.Hash) types.KeyDeriver {
	return &HKDFImpl{
		hashFunc: hashFunc,
	}
}
