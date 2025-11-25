package ed25519

import (
	"crypto/ed25519"

	"github.com/go-i2p/crypto/types"
)

// Ed25519PublicKey represents an Ed25519 public key for signature verification operations.
// This key type implements the SigningPublicKey interface and is used to verify digital
// signatures created by corresponding Ed25519 private keys. Public keys are 32 bytes in length.
//
// CRITICAL: Always use NewEd25519PublicKey() to create instances. Direct construction causes nil panics.
//
// WRONG - Will panic:
//
//	var key Ed25519PublicKey  // nil slice - Bytes() returns empty, causes runtime errors
//	copy(key[:], data)        // panic: copy to nil slice
//
// CORRECT - Use constructor:
//
//	key, err := ed25519.NewEd25519PublicKey(data)
//	if err != nil {
//	    return err
//	}
//
// Deprecated direct construction patterns (avoid in new code):
//
//	key, err := CreateEd25519PublicKeyFromBytes(data)  // Use NewEd25519PublicKey instead
//	key := make(Ed25519PublicKey, 32)                 // Unsafe, no validation
//	key := Ed25519PublicKey(data)                      // Unsafe, no validation
type Ed25519PublicKey []byte

// NewVerifier creates a verifier instance that can validate Ed25519 signatures.
// Returns a verifier configured with this public key for signature verification operations.
// The verifier can validate signatures created by the corresponding private key.
func (k Ed25519PublicKey) NewVerifier() (v types.Verifier, err error) {
	// Initialize verifier with this public key for signature validation
	temp := new(Ed25519Verifier)
	temp.k = k
	v = temp
	return temp, nil
}

// Len returns the length of the Ed25519 public key in bytes.
// Ed25519 public keys are always 32 bytes long as specified in RFC 8032.
// This method is useful for validation and serialization operations.
func (k Ed25519PublicKey) Len() int {
	return len(k)
}

// Bytes returns the raw byte representation of the Ed25519 public key.
// The returned slice contains the 32-byte public key data suitable for
// serialization, transmission, or storage operations.
func (k Ed25519PublicKey) Bytes() []byte {
	return k
}

// NOTE: Ed25519 is a signature algorithm, not an encryption algorithm.
// For I2P encryption operations, use Curve25519 (X25519) instead.
// This method has been removed to prevent cryptographic misuse.
//
// Use the curve25519 package for ECIES-X25519-AEAD encryption as required
// by I2P protocol specifications.

// createEd25519PublicKey creates an Ed25519 public key from byte data (legacy function).
// This function appears to contain a bug - it expects 256 bytes but Ed25519 public keys are 32 bytes.
// This function should not be used in new code; use CreateEd25519PublicKeyFromBytes instead.
func createEd25519PublicKey(data []byte) (k *ed25519.PublicKey) {
	log.WithField("data_length", len(data)).Debug("Creating Ed25519 public key")
	// Legacy logic with incorrect size expectation - should be 32 bytes, not 256
	if len(data) == 256 {
		k2 := ed25519.PublicKey{}
		copy(k2[:], data)
		k = &k2
		log.Debug("Ed25519 public key created successfully")
	} else {
		log.Warn("Invalid data length for Ed25519 public key")
	}
	return
}

// NewEd25519PublicKey creates a validated Ed25519 public key from bytes.
// This is the REQUIRED constructor - do not use var declarations or direct construction.
//
// Parameters:
//   - data: Must be exactly 32 bytes
//
// Returns error if data length is invalid.
//
// Example usage:
//
//	pubKey, err := ed25519.NewEd25519PublicKey(pubBytes)
//	if err != nil {
//	    return err
//	}
func NewEd25519PublicKey(data []byte) (Ed25519PublicKey, error) {
	return CreateEd25519PublicKeyFromBytes(data)
}

// CreateEd25519PublicKeyFromBytes constructs an Ed25519 public key from raw byte data.
// The input data must be exactly 32 bytes representing a valid Ed25519 public key.
// Returns an error if the data length doesn't match the required Ed25519 public key size.
//
// Deprecated: Use NewEd25519PublicKey instead. This function will be removed in v2.0.
func CreateEd25519PublicKeyFromBytes(data []byte) (Ed25519PublicKey, error) {
	log.WithField("data_length", len(data)).Debug("Creating Ed25519 public key")

	// Validate input meets Ed25519 public key size requirements
	if len(data) != ed25519.PublicKeySize {
		log.WithField("data_length", len(data)).Error("Invalid Ed25519 public key size")
		return nil, ErrInvalidPublicKeySize
	}

	// Return validated public key wrapped in our custom type
	// Return the Ed25519 public key
	log.Debug("Ed25519 public key created successfully")
	return Ed25519PublicKey(data), nil
}
