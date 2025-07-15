package dsa

import (
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
