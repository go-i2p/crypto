package dsa

import (
	"crypto/dsa"
	"crypto/rand"
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// DSAPrivateKey represents a DSA private key using a 20-byte array format.
// This type implements the I2P standard DSA private key representation where the
// private key value (X) is stored as a 160-bit (20-byte) big-endian integer.
// DSAPrivateKey satisfies the types.SigningPrivateKey interface for digital signatures.
//
// ⚠️ CRITICAL SECURITY WARNING:
// Do NOT use zero-value construction (var key DSAPrivateKey) as it creates an invalid
// all-zero key. Always use NewDSAPrivateKey() to ensure proper validation.
type DSAPrivateKey [20]byte

// NewDSAPrivateKey creates a validated DSA private key from bytes.
//
// This constructor validates that the provided data:
//   - Is exactly 20 bytes (160 bits) as required by I2P DSA specification
//   - Is non-zero (all-zero keys are cryptographically invalid)
//   - Is less than the DSA subgroup order q
//
// Parameters:
//   - data: Must be exactly 20 bytes representing the private exponent X
//
// Returns:
//   - DSAPrivateKey: A validated private key with defensive copy of the input
//   - error: If data is invalid (wrong size, all-zero, or >= q)
//
// Example:
//
//	keyBytes := make([]byte, 20)
//	_, _ = rand.Read(keyBytes)
//	key, err := NewDSAPrivateKey(keyBytes)
//	if err != nil {
//	    // Handle error - key is invalid
//	}
func NewDSAPrivateKey(data []byte) (DSAPrivateKey, error) {
	if len(data) != 20 {
		return DSAPrivateKey{}, oops.
			Code("invalid_key_size").
			With("expected", 20).
			With("actual", len(data)).
			Errorf("DSA private key must be exactly 20 bytes, got %d bytes", len(data))
	}

	// Validate key is non-zero and in valid range [1, q-1]
	x := new(big.Int).SetBytes(data)

	if x.Sign() == 0 {
		return DSAPrivateKey{}, oops.
			Code("zero_key").
			Errorf("DSA private key cannot be all zeros")
	}

	// Validate X < q (DSA subgroup order)
	// Note: DSA private keys are in the range [1, q-1] where q is 160-bit
	if x.Cmp(dsaq) >= 0 {
		return DSAPrivateKey{}, oops.
			Code("key_out_of_range").
			Errorf("DSA private key must be less than q")
	}

	// Create defensive copy
	var key DSAPrivateKey
	copy(key[:], data)
	return key, nil
}

// NewSigner creates a new DSA signer instance using this private key.
// The returned signer can generate DSA signatures for data and pre-computed hashes.
// Returns a DSASigner implementing the types.Signer interface or an error if
// the private key format is invalid or signer creation fails.
// Example usage: signer, err := privateKey.NewSigner()
func (k DSAPrivateKey) NewSigner() (s types.Signer, err error) {
	log.WithFields(logger.Fields{"pkg": "dsa", "func": "DSAPrivateKey.NewSigner"}).Debug("Creating new DSA signer")
	// Validate the private exponent X is in the DSA range [1, q-1] before
	// creating the signer; a zero or out-of-range key is an invalid format.
	x := new(big.Int).SetBytes(k[:])
	if x.Sign() == 0 || x.Cmp(dsaq) >= 0 {
		log.WithFields(logger.Fields{"pkg": "dsa", "func": "DSAPrivateKey.NewSigner"}).Error("Invalid DSA private key format")
		return nil, types.ErrInvalidKeyFormat
	}
	// Create signer with validated private key parameters
	s = &DSASigner{
		k: createDSAPrivkey(x),
	}
	return s, err
}

// Public extracts the corresponding DSA public key from this private key.
// This method derives the public key (Y = g^X mod p) using standard DSA mathematics
// without exposing the private key material. Returns the public key as DSAPublicKey
// or an error if the private key format is invalid or derivation fails.
func (k DSAPrivateKey) Public() (types.SigningPublicKey, error) {
	var pk DSAPublicKey
	// Convert private key to standard DSA format for public key derivation
	p := createDSAPrivkey(new(big.Int).SetBytes(k[:]))
	if p == nil {
		log.WithFields(logger.Fields{"pkg": "dsa", "func": "DSAPrivateKey.Public"}).Error("Invalid DSA private key format")
		return nil, types.ErrInvalidKeyFormat
	} else {
		// Extract public key value Y and store in I2P format: the 1024-bit
		// big-endian value, right-aligned (zero-padded on the left) in 128
		// bytes. big.Int.Bytes() returns the minimal encoding with leading
		// zeros stripped, so it must be copied to the END of the array; a
		// left-aligned copy would shift the value and corrupt ~1% of keys
		// (any Y whose top byte(s) are zero), breaking verification.
		yBytes := p.Y.Bytes()
		if len(yBytes) > len(pk) {
			log.WithFields(logger.Fields{"pkg": "dsa", "func": "DSAPrivateKey.Public"}).Error("DSA public key value Y is larger than 128 bytes")
			return nil, types.ErrInvalidKeyFormat
		}
		copy(pk[len(pk)-len(yBytes):], yBytes)
		log.WithFields(logger.Fields{"pkg": "dsa", "func": "DSAPrivateKey.Public"}).Debug("DSA public key derived successfully")
	}
	return pk, nil
}

// Len returns the length of this DSA private key in bytes.
// DSA private keys in I2P format are always 20 bytes (160 bits) as specified
// by the DSA standard for the private key value X. This method is required by
// the types.SigningPrivateKey interface for key size validation.
func (k DSAPrivateKey) Len() int {
	return len(k)
}

// Generate creates a new random DSA private key pair using cryptographically secure randomness.
// This method generates a fresh DSA private key using the standard I2P DSA parameters (1024-bit p, 160-bit q).
// The generated private key value X is securely random and mathematically valid for DSA operations.
// Returns a new DSAPrivateKey or an error if key generation fails due to insufficient entropy.
func (k DSAPrivateKey) Generate() (types.SigningPrivateKey, error) {
	log.WithFields(logger.Fields{"pkg": "dsa", "func": "DSAPrivateKey.Generate"}).Debug("Generating new DSA private key")
	// Use standard DSA key generation with I2P parameters
	dk := new(dsa.PrivateKey)
	err := generateDSA(dk, rand.Reader)
	if err == nil {
		// Convert generated key to I2P format: the 160-bit private exponent X,
		// right-aligned (zero-padded on the left) in 20 bytes, matching the
		// big-endian fixed-width encoding NewDSAPrivateKey/SetBytes expect.
		var newKey DSAPrivateKey
		xBytes := dk.X.Bytes()
		if len(xBytes) > len(newKey) {
			log.WithFields(logger.Fields{"pkg": "dsa", "func": "DSAPrivateKey.Generate"}).Error("Generated DSA private key X is larger than 20 bytes")
			return nil, types.ErrInvalidKeyFormat
		}
		copy(newKey[len(newKey)-len(xBytes):], xBytes)
		log.WithFields(logger.Fields{"pkg": "dsa", "func": "DSAPrivateKey.Generate"}).Debug("New DSA private key generated successfully")
		return newKey, nil
	} else {
		log.WithFields(logger.Fields{"pkg": "dsa", "func": "DSAPrivateKey.Generate"}).WithError(err).Error("Failed to generate new DSA private key")
		return nil, err
	}
}

// Bytes returns the raw byte representation of this DSA private key.
// The returned bytes contain the complete private key material in I2P format,
// representing the 160-bit private key value X as a big-endian integer.
// This method is required by the types.SigningPrivateKey interface.
func (k DSAPrivateKey) Bytes() []byte {
	return k[:]
}

// Zero securely clears all sensitive private key data from memory.
// This method overwrites the private key material with zeros to prevent
// memory disclosure attacks. After calling Zero, the key becomes unusable
// for cryptographic operations. This method is required by the types.SigningPrivateKey interface.
func (k *DSAPrivateKey) Zero() {
	// Overwrite private key material with zeros for security
	for i := range k {
		k[i] = 0
	}
	log.WithFields(logger.Fields{"pkg": "dsa", "func": "DSAPrivateKey.Zero"}).Debug("DSA private key securely erased")
}
