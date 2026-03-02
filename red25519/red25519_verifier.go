package red25519

import (
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	upstream "github.com/go-i2p/red25519"
	"github.com/samber/oops"
)

// Red25519Verifier provides digital signature verification using Red25519 (RedDSA).
//
// Unlike standard crypto/ed25519.Verify, Red25519 verification is intentionally
// stricter: it rejects all small-order public keys (points whose order divides
// the cofactor 8), which would allow trivial or near-trivial signature forgery.
type Red25519Verifier struct {
	k upstream.PublicKey
}

// VerifyHash validates a Red25519 signature against a pre-computed hash.
// For Red25519, VerifyHash treats the hash as the message, applying verification
// to the provided hash bytes.
// Returns an error if verification fails or inputs are invalid.
func (v *Red25519Verifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logger.Fields{
		"hash_length": len(h),
		"sig_length":  len(sig),
	}).Debug("Verifying Red25519 signature hash")

	return v.verify(h, sig)
}

// Verify validates a Red25519 signature against arbitrary data.
// Returns an error if verification fails.
func (v *Red25519Verifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logger.Fields{
		"data_length": len(data),
		"sig_length":  len(sig),
	}).Debug("Verifying Red25519 signature")

	return v.verify(data, sig)
}

// verify performs the actual Red25519 signature verification using the upstream library.
func (v *Red25519Verifier) verify(message, sig []byte) error {
	if len(sig) != SignatureSize {
		log.Error("Bad Red25519 signature size")
		return types.ErrBadSignatureSize
	}
	if len(v.k) != PublicKeySize {
		log.Error("Invalid Red25519 public key size")
		return oops.Errorf("failed to verify: invalid red25519 public key size")
	}

	ok := upstream.Verify(v.k, message, sig)
	if !ok {
		log.Warn("Invalid Red25519 signature")
		return oops.Errorf("failed to verify: invalid signature")
	}

	log.Debug("Red25519 signature verified successfully")
	return nil
}
