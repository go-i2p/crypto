package elg

import (
	"crypto/rand"
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/elgamal"
	"github.com/samber/oops"
)

type (
	// ElgPublicKey represents a 256-byte ElGamal public key used for encryption operations.
	// It stores the public key component in I2P's standard ElGamal format for secure communications.
	// Example usage: pubKey := ElgPublicKey{}; enc, err := pubKey.NewEncrypter()
	ElgPublicKey [256]byte
)

// Len returns the length of the ElGamal public key in bytes.
// Always returns 256 for I2P standard ElGamal key size.
func (elg ElgPublicKey) Len() int {
	return len(elg)
}

// Bytes returns the public key as a byte slice.
// Provides access to the raw key material for serialization and transmission.
func (elg ElgPublicKey) Bytes() []byte {
	return elg[:]
}

// NewEncrypter creates a new ElGamal encrypter using this public key.
// Returns a types.Encrypter interface that can encrypt data for the holder of the corresponding private key.
// Returns error if the public key data is invalid or encrypter creation fails.
func (elg ElgPublicKey) NewEncrypter() (enc types.Encrypter, err error) {
	log.Debug("Creating new ElGamal encrypter")
	// Convert raw key bytes to internal ElGamal structure
	k := createElgamalPublicKey(elg[:])
	// Create encryption session with secure random source
	enc, err = createElgamalEncryption(k, rand.Reader)
	if err != nil {
		log.WithError(err).Error("Failed to create ElGamal encrypter")
	} else {
		log.Debug("ElGamal encrypter created successfully")
	}
	return
}

// Generate creates a new ElGamal key pair and returns the public key component.
// This method generates a complete ElGamal key pair using I2P-standard parameters
// and returns only the public key portion. The private key is discarded for security.
// Returns an error if key generation fails due to entropy or parameter issues.
func (elg ElgPublicKey) Generate() (types.PublicEncryptionKey, error) {
	log.Debug("Generating new ElGamal public key")
	var privKey elgamal.PrivateKey

	// Generate complete key pair using secure parameters
	err := ElgamalGenerate(&privKey, nil)
	if err != nil {
		log.WithError(err).Error("ElGamal public key generation failed")
		return nil, oops.Errorf("failed to generate ElGamal public key: %w", err)
	}

	// Extract public component and convert to I2P format
	var result ElgPublicKey
	yBytes := privKey.Y.Bytes()

	// Ensure Y is exactly 256 bytes with leading zeros if necessary
	if len(yBytes) > 256 {
		log.Error("Generated public key Y component too large")
		return nil, oops.Errorf("invalid public key size: %d bytes", len(yBytes))
	}

	// Copy Y bytes to fixed-size array with proper padding
	copy(result[256-len(yBytes):], yBytes)
	log.Debug("ElGamal public key generated successfully")
	return result, nil
}

// createElgamalPublicKey converts a 256-byte slice to an ElGamal public key structure.
// Reconstructs the public key components from I2P's standard byte representation.
// Returns nil if the key data is invalid or corrupted.
// create an elgamal public key from byte slice
func createElgamalPublicKey(data []byte) (k *elgamal.PublicKey) {
	log.WithField("data_length", len(data)).Debug("Creating ElGamal public key")
	if len(data) == 256 {
		k = &elgamal.PublicKey{
			G: elgg,
			P: elgp,
			Y: new(big.Int).SetBytes(data),
		}
		log.Debug("ElGamal public key created successfully")
	} else {
		log.Warn("Invalid data length for ElGamal public key")
	}

	return
}
