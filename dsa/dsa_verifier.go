package dsa

import (
	"crypto/dsa"
	"crypto/sha1"
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
)

// DSAVerifier provides DSA digital signature verification functionality.
// This type implements the types.Verifier interface for validating DSA signatures
// using SHA-1 hash algorithm as specified by the I2P protocol. DSAVerifier wraps
// a standard crypto/dsa.PublicKey and provides I2P-compatible signature validation.
type DSAVerifier struct {
	k *dsa.PublicKey
}

// Verify validates a DSA signature against the provided data using SHA-1 hashing.
// This method first computes the SHA-1 hash of the input data, then validates the DSA
// signature using the standard DSA verification algorithm. The signature must be in I2P
// format as a 40-byte array containing r (20 bytes) followed by s (20 bytes).
// Returns nil if the signature is valid, or an error if verification fails.
func (v *DSAVerifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logger.Fields{
		"data_length": len(data),
		"sig_length":  len(sig),
	}).Debug("Verifying DSA signature")
	// Hash data with SHA-1 as required by I2P DSA specification
	h := sha1.Sum(data)
	err = v.VerifyHash(h[:], sig)
	return
}

// VerifyHash validates a DSA signature against a pre-computed hash digest.
// This method validates a DSA signature directly from a hash digest using the DSA
// verification algorithm. The hash should be 20 bytes (SHA-1) and the signature
// must be 40 bytes in I2P format (r||s). Returns nil if the signature is mathematically
// valid for the hash, or an error if verification fails. This is the primary verification
// method for performance-critical applications.
func (v *DSAVerifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logger.Fields{
		"hash_length": len(h),
		"sig_length":  len(sig),
	}).Debug("Verifying DSA signature hash")
	// Validate signature format (must be exactly 40 bytes for I2P DSA)
	if len(sig) == 40 {
		// Extract r and s values from I2P signature format
		r := new(big.Int).SetBytes(sig[:20])
		s := new(big.Int).SetBytes(sig[20:])
		// Perform cryptographic signature verification using DSA algorithm
		if dsa.Verify(v.k, h, r, s) {
			// Signature is mathematically valid
			log.Debug("DSA signature verified successfully")
		} else {
			// Signature verification failed - cryptographically invalid
			log.Warn("Invalid DSA signature")
			err = types.ErrInvalidSignature
		}
	} else {
		// Signature length is incorrect for DSA format
		log.Error("Bad DSA signature size")
		err = types.ErrBadSignatureSize
	}
	return
}
