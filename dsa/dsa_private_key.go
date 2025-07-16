package dsa

import (
	"crypto/dsa"
	"crypto/rand"
	"math/big"

	"github.com/go-i2p/crypto/types"
)

// DSAPrivateKey represents a DSA private key using a 20-byte array format.
// This type implements the I2P standard DSA private key representation where the
// private key value (X) is stored as a 160-bit (20-byte) big-endian integer.
// DSAPrivateKey satisfies the types.SigningPrivateKey interface for digital signatures.
type DSAPrivateKey [20]byte

// NewSigner creates a new DSA signer instance using this private key.
// The returned signer can generate DSA signatures for data and pre-computed hashes.
// Returns a DSASigner implementing the types.Signer interface or an error if
// the private key format is invalid or signer creation fails.
// Example usage: signer, err := privateKey.NewSigner()
func (k DSAPrivateKey) NewSigner() (s types.Signer, err error) {
	log.Debug("Creating new DSA signer")
	// Create signer with validated private key parameters
	s = &DSASigner{
		k: createDSAPrivkey(new(big.Int).SetBytes(k[:])),
	}
	return
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
		log.Error("Invalid DSA private key format")
		return nil, types.ErrInvalidKeyFormat
	} else {
		// Extract public key value Y and store in I2P format (128 bytes)
		copy(pk[:], p.Y.Bytes())
		log.Debug("DSA public key derived successfully")
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
	log.Debug("Generating new DSA private key")
	// Use standard DSA key generation with I2P parameters
	dk := new(dsa.PrivateKey)
	err := generateDSA(dk, rand.Reader)
	if err == nil {
		// Convert generated key to I2P format (20-byte private exponent)
		var newKey DSAPrivateKey
		copy(newKey[:], dk.X.Bytes())
		log.Debug("New DSA private key generated successfully")
		return newKey, nil
	} else {
		log.WithError(err).Error("Failed to generate new DSA private key")
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
	log.Debug("DSA private key securely erased")
}
