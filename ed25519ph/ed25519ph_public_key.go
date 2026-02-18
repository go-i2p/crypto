package ed25519ph

import (
	"crypto/ed25519"

	"github.com/go-i2p/crypto/types"
)

// Ed25519phPublicKey represents an Ed25519 public key for Ed25519ph signature verification.
// The key format is identical to standard Ed25519 (32 bytes), but the verification
// algorithm uses pre-hashing with SHA-512 and domain separation per RFC 8032 §5.1.
//
// CRITICAL: Always use NewEd25519phPublicKey() to create instances.
//
// WRONG - Unsafe:
//
//	var key Ed25519phPublicKey  // Zero value - cryptographically invalid
//
// CORRECT - Use constructor:
//
//	pubKey, err := ed25519ph.NewEd25519phPublicKey(pubBytes)
//	if err != nil {
//	    return err
//	}
type Ed25519phPublicKey []byte

// NewVerifier creates a verifier instance that can validate Ed25519ph signatures.
// Returns a verifier configured with this public key for Ed25519ph signature verification.
// The verifier uses pre-hashing and domain separation per RFC 8032 §5.1.
func (k Ed25519phPublicKey) NewVerifier() (v types.Verifier, err error) {
	temp := new(Ed25519phVerifier)
	temp.k = k
	v = temp
	return temp, nil
}

// Len returns the length of the Ed25519ph public key in bytes.
// Ed25519 public keys are always 32 bytes long as specified in RFC 8032.
func (k Ed25519phPublicKey) Len() int {
	return len(k)
}

// Bytes returns the raw byte representation of the Ed25519ph public key.
// The returned slice contains the 32-byte public key data suitable for
// serialization, transmission, or storage operations.
func (k Ed25519phPublicKey) Bytes() []byte {
	return k
}

// NewEd25519phPublicKey creates a validated Ed25519ph public key from bytes.
// This is the REQUIRED constructor - do not use var declarations or direct construction.
//
// Parameters:
//   - data: Must be exactly 32 bytes
//
// Returns error if data length is invalid.
func NewEd25519phPublicKey(data []byte) (Ed25519phPublicKey, error) {
	log.WithField("data_length", len(data)).Debug("Creating Ed25519ph public key")

	if len(data) != ed25519.PublicKeySize {
		log.WithField("data_length", len(data)).Error("Invalid Ed25519ph public key size")
		return nil, ErrInvalidPublicKeySize
	}

	key := make(Ed25519phPublicKey, ed25519.PublicKeySize)
	copy(key, data)
	return key, nil
}
