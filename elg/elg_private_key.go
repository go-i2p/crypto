package elg

import (
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/elgamal"
	"github.com/samber/oops"
)

type (
	// ElgPrivateKey represents a 256-byte ElGamal private key used for decryption operations.
	// It stores the private exponent in I2P's standard ElGamal format for anonymous networking.
	// Example usage: privKey := ElgPrivateKey{}; dec, err := privKey.NewDecrypter()
	ElgPrivateKey [256]byte
)

// Len returns the length of the ElGamal private key in bytes.
// Always returns 256 for I2P standard ElGamal key size.
func (elg ElgPrivateKey) Len() int {
	return len(elg)
}

// NewDecrypter creates a new ElGamal decrypter using this private key.
// Returns a types.Decrypter interface that can decrypt data encrypted with the corresponding public key.
// Returns error if the private key data is invalid or not in the valid range [1, p-1].
func (elg ElgPrivateKey) NewDecrypter() (dec types.Decrypter, err error) {
	log.Debug("Creating new ElGamal decrypter")
	k := createElgamalPrivateKey(elg[:])
	if k == nil {
		err = oops.Errorf("failed to create ElGamal private key: invalid key data")
		log.WithError(err).Error("ElGamal decrypter creation failed")
		return
	}
	dec = &elgDecrypter{
		k: k,
	}
	log.Debug("ElGamal decrypter created successfully")
	return
}

// Bytes returns the raw byte representation of this ElGamal private key.
// The returned bytes contain the complete private key material in I2P format,
// representing the 256-byte private exponent as a big-endian integer.
// This method is required by the types.PrivateEncryptionKey interface.
func (elg ElgPrivateKey) Bytes() []byte {
	return elg[:]
}

// Public extracts and returns the corresponding ElGamal public key.
// This method derives the public key (Y = g^X mod p) from the private key
// without exposing sensitive private key material. Returns the public key
// as ElgPublicKey or an error if key derivation fails.
func (elg ElgPrivateKey) Public() (types.PublicEncryptionKey, error) {
	log.Debug("Deriving ElGamal public key from private key")
	// Create temporary private key to compute public component
	privKey := createElgamalPrivateKey(elg[:])
	if privKey == nil {
		log.Error("Failed to create private key for public key derivation")
		return nil, oops.Errorf("invalid private key format for public key derivation")
	}

	// Extract Y component and convert to ElgPublicKey format
	var pubKey ElgPublicKey
	yBytes := privKey.Y.Bytes()

	// Ensure Y is exactly 256 bytes with leading zeros if necessary
	if len(yBytes) > 256 {
		log.Error("Public key Y component too large")
		return nil, oops.Errorf("invalid public key size: %d bytes", len(yBytes))
	}

	// Copy Y bytes to fixed-size array with proper padding
	copy(pubKey[256-len(yBytes):], yBytes)
	log.Debug("ElGamal public key derived successfully")
	return pubKey, nil
}

// Zero securely clears all sensitive private key data from memory.
// This method should be called when the private key is no longer needed to prevent
// memory disclosure attacks. After calling Zero, the key becomes unusable.
func (elg ElgPrivateKey) Zero() {
	// Clear each byte to prevent memory leakage
	for i := range elg {
		elg[i] = 0
	}
}

// Generate creates a new random ElGamal private key.
// This method generates a cryptographically secure private key in the valid range [1, p-1]
// using I2P's standard ElGamal parameters. Returns the generated private key or an error
// if key generation fails due to insufficient entropy or parameter validation.
func (elg ElgPrivateKey) Generate() (types.PrivateEncryptionKey, error) {
	log.Debug("Generating new ElGamal private key")
	var privKey elgamal.PrivateKey

	// Generate key using I2P ElGamal parameters and secure entropy
	err := ElgamalGenerate(&privKey, nil)
	if err != nil {
		log.WithError(err).Error("ElGamal key generation failed")
		return nil, oops.Errorf("failed to generate ElGamal key: %w", err)
	}

	// Convert generated key to I2P byte format
	var result ElgPrivateKey
	xBytes := privKey.X.Bytes()

	// Ensure X is exactly 256 bytes with leading zeros if necessary
	if len(xBytes) > 256 {
		log.Error("Generated private key X component too large")
		return nil, oops.Errorf("invalid private key size: %d bytes", len(xBytes))
	}

	// Copy X bytes to fixed-size array with proper padding
	copy(result[256-len(xBytes):], xBytes)
	log.Debug("ElGamal private key generated successfully")
	return result, nil
}

// createElgamalPrivateKey converts a 256-byte slice to an ElGamal private key structure.
// Validates that the private key is in the valid cryptographic range [1, p-1] where p is the ElGamal prime.
// Returns nil if the key data is invalid or outside the acceptable range.
// create an elgamal private key from byte slice
func createElgamalPrivateKey(data []byte) (k *elgamal.PrivateKey) {
	log.WithField("data_length", len(data)).Debug("Creating ElGamal private key")
	if len(data) != 256 {
		log.Warn("Invalid data length for ElGamal private key")
		return nil
	}

	x := new(big.Int).SetBytes(data)

	// Validate that private key is in valid range [1, p-1]
	// This ensures the key can be used for secure ElGamal operations
	if x.Cmp(one) < 0 || x.Cmp(new(big.Int).Sub(elgp, one)) >= 0 {
		log.Warn("Private key not in valid range [1, p-1]")
		return nil
	}

	// Compute corresponding public key y = g^x mod p
	// This derives the public component from the private exponent
	y := new(big.Int).Exp(elgg, x, elgp)
	k = &elgamal.PrivateKey{
		PublicKey: elgamal.PublicKey{
			Y: y,
			G: elgg,
			P: elgp,
		},
		X: x,
	}
	log.Debug("ElGamal private key created successfully")
	return
}
