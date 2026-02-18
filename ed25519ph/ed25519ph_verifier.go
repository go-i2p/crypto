package ed25519ph

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Ed25519phVerifier provides digital signature verification using the Ed25519ph
// (pre-hashed) variant defined in RFC 8032 §5.1.
//
// This verifier expects signatures produced by Ed25519ph (with domain separation).
// It cannot verify standard Ed25519 (PureEdDSA) signatures.
type Ed25519phVerifier struct {
	k []byte
}

// VerifyHash validates an Ed25519ph signature against a pre-computed SHA-512 hash.
// The hash must be exactly 64 bytes (SHA-512 output). Verification uses Ed25519ph
// domain separation per RFC 8032 §5.1.
// Returns an error if verification fails or inputs are invalid.
func (v *Ed25519phVerifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logger.Fields{
		"hash_length": len(h),
		"sig_length":  len(sig),
	}).Debug("Verifying Ed25519ph signature hash")

	if len(sig) != ed25519.SignatureSize {
		log.Error("Bad Ed25519ph signature size")
		err = types.ErrBadSignatureSize
		return
	}
	if len(v.k) != ed25519.PublicKeySize {
		log.Error("Invalid Ed25519ph public key size")
		err = oops.Errorf("failed to verify: invalid ed25519ph public key size")
		return
	}

	// Verify using Ed25519ph mode via VerifyWithOptions with Hash: crypto.SHA512
	// This checks the RFC 8032 Ed25519ph domain separation tag
	opts := &ed25519.Options{Hash: crypto.SHA512}
	verifyErr := ed25519.VerifyWithOptions(v.k, h, sig, opts)
	if verifyErr != nil {
		log.Warn("Invalid Ed25519ph signature")
		err = oops.Errorf("failed to verify: invalid signature")
	} else {
		log.Debug("Ed25519ph signature verified successfully")
	}
	return
}

// Verify validates an Ed25519ph signature against arbitrary data.
// The data is first hashed with SHA-512, then verified using Ed25519ph with
// domain separation as specified in RFC 8032 §5.1.
// Returns an error if verification fails.
func (v *Ed25519phVerifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logger.Fields{
		"data_length": len(data),
		"sig_length":  len(sig),
	}).Debug("Verifying Ed25519ph signature")

	// Hash the data with SHA-512 before verification
	h := sha512.Sum512(data)
	err = v.VerifyHash(h[:], sig)
	return
}
