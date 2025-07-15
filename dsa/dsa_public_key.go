package dsa

import (
	"math/big"

	"github.com/go-i2p/crypto/types"
)

type DSAPublicKey [128]byte

func (k DSAPublicKey) Bytes() []byte {
	return k[:]
}

// create a new dsa verifier
func (k DSAPublicKey) NewVerifier() (v types.Verifier, err error) {
	log.Debug("Creating new DSA verifier")
	v = &DSAVerifier{
		k: createDSAPublicKey(new(big.Int).SetBytes(k[:])),
	}
	return
}

func (k DSAPublicKey) Len() int {
	return len(k)
}
