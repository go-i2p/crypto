package dsa

import (
	"crypto/dsa"
	"crypto/rand"
	"math/big"

	"github.com/go-i2p/crypto/types"
)

type DSAPrivateKey [20]byte

// create a new dsa signer
func (k DSAPrivateKey) NewSigner() (s types.Signer, err error) {
	log.Debug("Creating new DSA signer")
	s = &DSASigner{
		k: createDSAPrivkey(new(big.Int).SetBytes(k[:])),
	}
	return
}

func (k DSAPrivateKey) Public() (types.SigningPublicKey, error) {
	var pk DSAPublicKey
	p := createDSAPrivkey(new(big.Int).SetBytes(k[:]))
	if p == nil {
		log.Error("Invalid DSA private key format")
		return nil, types.ErrInvalidKeyFormat
	} else {
		copy(pk[:], p.Y.Bytes())
		log.Debug("DSA public key derived successfully")
	}
	return pk, nil
}

func (k DSAPrivateKey) Len() int {
	return len(k)
}

func (k DSAPrivateKey) Generate() (types.SigningPrivateKey, error) {
	log.Debug("Generating new DSA private key")
	dk := new(dsa.PrivateKey)
	err := generateDSA(dk, rand.Reader)
	if err == nil {
		var newKey DSAPrivateKey
		copy(newKey[:], dk.X.Bytes())
		log.Debug("New DSA private key generated successfully")
		return newKey, nil
	} else {
		log.WithError(err).Error("Failed to generate new DSA private key")
		return nil, err
	}
}
