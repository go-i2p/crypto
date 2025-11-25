package hkdf

import (
	"crypto/sha256"
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
//
// ⚠️ CRITICAL SECURITY WARNING:
// Do NOT construct HKDFImpl directly using var or struct literals.
// Zero-value construction with nil hashFunc will default to SHA-256, but this implicit
// behavior should not be relied upon. Always use constructors for explicit configuration.
//
// WRONG - Implicit behavior:
//
//	var deriver HKDFImpl              // hashFunc is nil - relies on fallback
//	deriver := HKDFImpl{}             // hashFunc is nil - relies on fallback
//
// CORRECT - Use constructors:
//
//	// For SHA-256 (recommended default):
//	deriver := hkdf.NewHKDF()
//
//	// For custom hash function:
//	deriver := hkdf.NewHKDFWithHash(sha512.New)
type HKDFImpl struct {
	// hashFunc specifies the hash function for HKDF operations.
	// When nil, defaults to SHA-256 for compatibility with I2P cryptographic standards.
	// Custom hash functions can be provided for specialized use cases.
	hashFunc func() hash.Hash
}

// NewHKDF creates a new HKDF key deriver using SHA-256 hash function.
// This is the recommended constructor for most use cases.
//
// SHA-256 is selected as the default hash function because:
//   - Provides 256-bit security level suitable for most applications
//   - Well-tested and widely deployed in I2P protocol
//   - Optimal balance between security and performance
//
// Returns a types.KeyDeriver that implements RFC 5869 HKDF for secure key expansion
// with default parameters optimized for I2P cryptographic operations.
//
// Example usage:
//
//	deriver := hkdf.NewHKDF()
//	key, err := deriver.Derive(ikm, salt, info, 32)
//	if err != nil {
//	    return err
//	}
func NewHKDF() types.KeyDeriver {
	return &HKDFImpl{
		hashFunc: sha256.New, // Explicitly set to SHA-256
	}
}

// NewHKDFWithHash creates a new HKDF key deriver with a custom hash function.
//
// This constructor allows specification of alternative hash algorithms for specialized
// cryptographic requirements while maintaining RFC 5869 compliance.
//
// Parameters:
//   - hashFunc: Hash function constructor (e.g., sha256.New, sha512.New)
//
// Panics if hashFunc is nil. Use NewHKDF() for the default SHA-256 hash function.
//
// Example usage:
//
//	// For SHA-512 based key derivation:
//	deriver := hkdf.NewHKDFWithHash(sha512.New)
//
//	// For SHA-384:
//	deriver := hkdf.NewHKDFWithHash(sha512.New384)
func NewHKDFWithHash(hashFunc func() hash.Hash) types.KeyDeriver {
	if hashFunc == nil {
		panic("hashFunc cannot be nil - use NewHKDF() for default SHA-256")
	}
	return &HKDFImpl{
		hashFunc: hashFunc,
	}
}
