package curve25519

import (
	"crypto/sha512"

	"github.com/go-i2p/crypto/types"
	"github.com/sirupsen/logrus"
	"go.step.sm/crypto/x25519"
)

// Curve25519Verifier handles Curve25519-based digital signature verification operations.
// This type implements the types.Verifier interface and provides X25519 elliptic curve signature
// verification using SHA-512 hashing for authenticating data integrity in I2P network protocols.
type Curve25519Verifier struct {
	k []byte // Public key material for signature verification operations
}

// VerifyHash verifies a digital signature against a pre-computed hash using Curve25519 cryptography.
// This method validates that the signature was created by the private key corresponding to this public key
// using the provided hash. The hash should typically be computed using SHA-512 for security.
// Returns types.ErrBadSignatureSize for invalid signature length, ErrInvalidPublicKey for invalid key,
// or ErrInvalidSignature if verification fails.
func (v *Curve25519Verifier) VerifyHash(h, sig []byte) error {
	log.WithFields(logrus.Fields{
		"hash_length":      len(h),
		"signature_length": len(sig),
	}).Debug("Verifying hash with Curve25519")

	if len(sig) != x25519.SignatureSize {
		log.Error("Bad signature size")
		return types.ErrBadSignatureSize
	}

	if len(v.k) != x25519.PublicKeySize {
		log.Error("Invalid Curve25519 public key size")
		return ErrInvalidPublicKey
	}

	// Perform cryptographic signature verification using X25519 algorithms
	if !x25519.Verify(v.k, h, sig) {
		log.Error("Invalid signature")
		return ErrInvalidSignature
	}

	log.Debug("Hash verified successfully")
	return nil
}

// Verify verifies a digital signature against the provided data using Curve25519 cryptography.
// This method automatically hashes the input data using SHA-512 before verification to ensure data integrity.
// It validates that the signature was created by the private key corresponding to this public key
// using the provided data. This is the primary method for signature verification in I2P protocols.
func (v *Curve25519Verifier) Verify(data, sig []byte) error {
	log.WithFields(logrus.Fields{
		"data_length":      len(data),
		"signature_length": len(sig),
	}).Debug("Verifying data with Curve25519")

	// Hash the data using SHA-512 for cryptographic security before verification
	h := sha512.Sum512(data)
	return v.VerifyHash(h[:], sig)
}
