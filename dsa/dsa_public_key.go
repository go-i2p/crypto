package dsa

import (
	"math/big"

	"github.com/go-i2p/crypto/types"
)

// DSAPublicKey represents a DSA public key using a 128-byte array format.
// This type implements the I2P standard DSA public key representation where the
// public key value (Y = g^X mod p) is stored as a 1024-bit (128-byte) big-endian integer.
// DSAPublicKey satisfies the types.SigningPublicKey interface for signature verification.
type DSAPublicKey [128]byte

// Bytes returns the raw byte representation of this DSA public key.
// The returned bytes contain the complete public key material in I2P format,
// representing the 1024-bit public key value Y as a big-endian integer.
// This method is required by the types.SigningPublicKey interface.
func (k DSAPublicKey) Bytes() []byte {
	return k[:]
}

// NewVerifier creates a new DSA signature verifier using this public key.
// The returned verifier can validate DSA signatures against data and pre-computed hashes.
// Returns a DSAVerifier implementing the types.Verifier interface or an error if
// the public key format is invalid or verifier creation fails.
// Example usage: verifier, err := publicKey.NewVerifier()
func (k DSAPublicKey) NewVerifier() (v types.Verifier, err error) {
	log.Debug("Creating new DSA verifier")
	// Create verifier with validated public key parameters
	v = &DSAVerifier{
		k: createDSAPublicKey(new(big.Int).SetBytes(k[:])),
	}
	return
}

// Len returns the length of this DSA public key in bytes.
// DSA public keys in I2P format are always 128 bytes (1024 bits) as specified
// by the I2P DSA standard. This method is required by the types.SigningPublicKey
// interface for key size validation and serialization purposes.
func (k DSAPublicKey) Len() int {
	return len(k)
}

// Verify validates a DSA signature against the provided data using this public key.
// This method provides a convenient interface for signature verification by creating
// a verifier instance and calling its Verify method. The signature must be in I2P
// format as a 40-byte array. Returns nil if the signature is valid, or an error if
// verification fails or the key/signature format is invalid.
func (k DSAPublicKey) Verify(data, sig []byte) error {
	// Create temporary verifier for one-time signature verification
	verifier, err := k.NewVerifier()
	if err != nil {
		return err
	}
	return verifier.Verify(data, sig)
}

// VerifyHash validates a DSA signature against a pre-computed hash using this public key.
// This method provides a convenient interface for hash signature verification by creating
// a verifier instance and calling its VerifyHash method. The hash should be 20 bytes (SHA-1)
// and the signature must be 40 bytes in I2P format. Returns nil if the signature is valid.
func (k DSAPublicKey) VerifyHash(h, sig []byte) error {
	// Create temporary verifier for one-time hash signature verification
	verifier, err := k.NewVerifier()
	if err != nil {
		return err
	}
	return verifier.VerifyHash(h, sig)
}
