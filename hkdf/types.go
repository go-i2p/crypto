package hkdf

import (
	"hash"

	"github.com/go-i2p/crypto/types"
)

// HKDFKey provides a standard entry point for HKDF key derivation operations.
// This type implements the I2P cryptographic interface pattern, allowing creation of
// key derivers that follow RFC 5869 HKDF specification for secure key expansion.
type HKDFKey struct{}

// NewDeriver returns a types.KeyDeriver for HKDF
func (k HKDFKey) NewDeriver() types.KeyDeriver {
	return NewHKDF()
}

// HKDFImpl provides the concrete implementation of HKDF key derivation using SHA-256.
// This structure encapsulates the hash function and implements the types.KeyDeriver interface
// for extracting and expanding cryptographic keys according to RFC 5869 specification.
type HKDFImpl struct {
	// hashFunc specifies the hash function for HKDF operations.
	// When nil, defaults to SHA-256 for compatibility with I2P cryptographic standards.
	// Custom hash functions can be provided for specialized use cases.
	hashFunc func() hash.Hash
}

// NewHKDF creates a new HKDF key deriver using SHA-256 hash function.
// Returns a types.KeyDeriver that implements RFC 5869 HKDF for secure key expansion
// with default parameters optimized for I2P cryptographic operations.
// NewHKDF returns a types.KeyDeriver for HKDF using SHA-256
func NewHKDF() types.KeyDeriver {
	return &HKDFImpl{
		hashFunc: nil, // Will default to SHA-256 in implementation
	}
}

// NewHKDFWithHash creates a new HKDF key deriver with a custom hash function.
// Allows specification of alternative hash algorithms for specialized cryptographic
// requirements while maintaining RFC 5869 compliance.
// Example: hkdf := NewHKDFWithHash(sha512.New) for SHA-512 based key derivation.
// NewHKDFWithHash returns a types.KeyDeriver for HKDF using a custom hash function
func NewHKDFWithHash(hashFunc func() hash.Hash) types.KeyDeriver {
	return &HKDFImpl{
		hashFunc: hashFunc,
	}
}
