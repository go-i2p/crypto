package dsa

import (
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// DSAPublicKey represents a DSA public key using a 128-byte array format.
// This type implements the I2P standard DSA public key representation where the
// public key value (Y = g^X mod p) is stored as a 1024-bit (128-byte) big-endian integer.
// DSAPublicKey satisfies the types.SigningPublicKey interface for signature verification.
//
// ⚠️ CRITICAL SECURITY WARNING:
// Do NOT use zero-value construction (var key DSAPublicKey) as it creates an invalid
// all-zero key. Always use NewDSAPublicKey() to ensure proper validation.
type DSAPublicKey [128]byte

// NewDSAPublicKey creates a validated DSA public key from bytes.
//
// This constructor validates that the provided data:
//   - Is exactly 128 bytes (1024 bits) as required by I2P DSA specification
//   - Is non-zero (all-zero keys are cryptographically invalid)
//   - Is in valid range [2, p-1] where p is the DSA prime modulus
//
// Parameters:
//   - data: Must be exactly 128 bytes representing the public value Y
//
// Returns:
//   - DSAPublicKey: A validated public key with defensive copy of the input
//   - error: If data is invalid (wrong size, zero/one, or >= p)
//
// Example:
//
//	privKey, _ := NewDSAPrivateKey(privBytes)
//	pubKey, err := privKey.Public()
//	if err != nil {
//	    // Handle error
//	}
func NewDSAPublicKey(data []byte) (DSAPublicKey, error) {
	if len(data) != 128 {
		return DSAPublicKey{}, oops.
			Code("invalid_key_size").
			With("expected", 128).
			With("actual", len(data)).
			Errorf("DSA public key must be exactly 128 bytes, got %d bytes", len(data))
	}

	// Validate key is non-zero and in valid range [2, p-1]
	y := new(big.Int).SetBytes(data)

	if y.Sign() == 0 {
		return DSAPublicKey{}, oops.
			Code("zero_key").
			Errorf("DSA public key cannot be all zeros")
	}

	// Reject Y=1 (cryptographically weak)
	one := big.NewInt(1)
	if y.Cmp(one) == 0 {
		return DSAPublicKey{}, oops.
			Code("weak_key").
			Errorf("DSA public key cannot be 1 (cryptographically weak)")
	}

	// Validate Y < p (DSA modulus)
	if y.Cmp(dsap) >= 0 {
		return DSAPublicKey{}, oops.
			Code("key_out_of_range").
			Errorf("DSA public key must be less than p")
	}

	// Create defensive copy
	var key DSAPublicKey
	copy(key[:], data)
	return key, nil
}

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
