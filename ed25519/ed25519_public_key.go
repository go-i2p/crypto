package ed25519

import (
	"crypto/ed25519"

	"github.com/go-i2p/crypto/types"
)

type Ed25519PublicKey []byte

func (k Ed25519PublicKey) NewVerifier() (v types.Verifier, err error) {
	temp := new(Ed25519Verifier)
	temp.k = k
	v = temp
	return temp, nil
}

func (k Ed25519PublicKey) Len() int {
	return len(k)
}

func (k Ed25519PublicKey) Bytes() []byte {
	return k
}

// NOTE: Ed25519 is a signature algorithm, not an encryption algorithm.
// For I2P encryption operations, use Curve25519 (X25519) instead.
// This method has been removed to prevent cryptographic misuse.
//
// Use the curve25519 package for ECIES-X25519-AEAD encryption as required
// by I2P protocol specifications.

func createEd25519PublicKey(data []byte) (k *ed25519.PublicKey) {
	log.WithField("data_length", len(data)).Debug("Creating Ed25519 public key")
	if len(data) == 256 {
		k2 := ed25519.PublicKey{}
		copy(k2[:], data)
		k = &k2
		log.Debug("Ed25519 public key created successfully")
	} else {
		log.Warn("Invalid data length for Ed25519 public key")
	}
	return
}

func CreateEd25519PublicKeyFromBytes(data []byte) (Ed25519PublicKey, error) {
	log.WithField("data_length", len(data)).Debug("Creating Ed25519 public key")

	if len(data) != ed25519.PublicKeySize {
		log.WithField("data_length", len(data)).Error("Invalid Ed25519 public key size")
		return nil, ErrInvalidPublicKeySize
	}

	// Return the Ed25519 public key
	log.Debug("Ed25519 public key created successfully")
	return Ed25519PublicKey(data), nil
}
