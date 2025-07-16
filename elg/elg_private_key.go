package elg

import (
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
	"golang.org/x/crypto/openpgp/elgamal"
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
