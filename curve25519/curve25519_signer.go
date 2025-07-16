package curve25519

import (
	"crypto/rand"
	"crypto/sha512"

	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

// Curve25519Signer handles Curve25519-based digital signature creation operations.
// This type implements the types.Signer interface and provides X25519 elliptic curve signature
// generation using SHA-512 hashing for data integrity and authentication in I2P network protocols.
type Curve25519Signer struct {
	k []byte // Private key material for signature operations
}

// Sign creates a digital signature of the provided data using Curve25519 cryptography.
// This method automatically hashes the input data using SHA-512 before signing to ensure data integrity.
// The signature can be verified using the corresponding Curve25519 public key and the original data.
// Returns ErrInvalidPrivateKey if the private key size is invalid (must be 32 bytes).
func (s *Curve25519Signer) Sign(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Signing data with Curve25519")

	if len(s.k) != x25519.PrivateKeySize {
		log.Error("Invalid Curve25519 private key size")
		return nil, ErrInvalidPrivateKey
	}

	// Hash the data using SHA-512 for cryptographic security before signing
	h := sha512.Sum512(data)
	return s.SignHash(h[:])
}

// SignHash creates a digital signature of a pre-computed hash using Curve25519 cryptography.
// This method accepts a pre-hashed input (typically SHA-512) and creates a cryptographic signature
// using X25519 elliptic curve algorithms. This is useful when the hash has already been computed
// or when implementing custom hash functions for specific I2P protocol requirements.
func (s *Curve25519Signer) SignHash(h []byte) ([]byte, error) {
	log.WithField("hash_length", len(h)).Debug("Signing hash with Curve25519")

	sig, err := x25519.Sign(rand.Reader, s.k, h)
	if err != nil {
		log.WithError(err).Error("Failed to sign hash")
		return nil, oops.Errorf("failed to sign: %w", err)
	}

	log.WithField("signature_length", len(sig)).Debug("Hash signed successfully")
	return sig, nil
}
