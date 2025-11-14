package ed25519

import (
	"crypto/ed25519"
	"crypto/sha512"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Ed25519Verifier provides digital signature verification using Ed25519 public keys.
// This type implements the Verifier interface for validating cryptographic signatures
// created by Ed25519 private keys against the corresponding public key.
type Ed25519Verifier struct {
	k []byte
}

// VerifyHash validates an Ed25519 signature against a pre-computed hash.
// This method verifies the signature directly against the provided hash without
// additional hashing. Returns an error if verification fails or inputs are invalid.
func (v *Ed25519Verifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logger.Fields{
		"hash_length": len(h),
		"sig_length":  len(sig),
	}).Debug("Verifying Ed25519 signature hash")

	// Validate signature size meets Ed25519 requirements
	if len(sig) != ed25519.SignatureSize {
		log.Error("Bad Ed25519 signature size")
		err = types.ErrBadSignatureSize
		return
	}
	// Validate public key size before verification
	if len(v.k) != ed25519.PublicKeySize {
		log.Error("Invalid Ed25519 public key size")
		err = oops.Errorf("failed to verify: invalid ed25519 public key size")
		return
	}

	// Perform cryptographic signature verification using standard library
	ok := ed25519.Verify(v.k, h, sig)
	if !ok {
		log.Warn("Invalid Ed25519 signature")
		err = oops.Errorf("failed to verify: invalid signature")
	} else {
		log.Debug("Ed25519 signature verified successfully")
	}
	return
}

// Verify validates an Ed25519 signature against arbitrary data.
// The data is first hashed using SHA-512 before verification to ensure
// consistent validation. Returns an error if verification fails.
func (v *Ed25519Verifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logger.Fields{
		"data_length": len(data),
		"sig_length":  len(sig),
	}).Debug("Verifying Ed25519 signature")

	// Hash the data with SHA-512 before signature verification
	h := sha512.Sum512(data)
	err = v.VerifyHash(h[:], sig)
	return
}
