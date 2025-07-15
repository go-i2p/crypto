package elg

import (
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
	"golang.org/x/crypto/openpgp/elgamal"
)

type (
	ElgPrivateKey [256]byte
)

func (elg ElgPrivateKey) Len() int {
	return len(elg)
}

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

// create an elgamal private key from byte slice
func createElgamalPrivateKey(data []byte) (k *elgamal.PrivateKey) {
	log.WithField("data_length", len(data)).Debug("Creating ElGamal private key")
	if len(data) != 256 {
		log.Warn("Invalid data length for ElGamal private key")
		return nil
	}

	x := new(big.Int).SetBytes(data)

	// Validate that private key is in valid range [1, p-1]
	if x.Cmp(one) < 0 || x.Cmp(new(big.Int).Sub(elgp, one)) >= 0 {
		log.Warn("Private key not in valid range [1, p-1]")
		return nil
	}

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
