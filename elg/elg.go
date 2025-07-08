package elgamal

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"math/big"

	"github.com/go-i2p/crypto/rand"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"

	"golang.org/x/crypto/openpgp/elgamal"
)

type PrivateKey struct {
	elgamal.PrivateKey
}

// generate an elgamal key pair
func ElgamalGenerate(priv *elgamal.PrivateKey, _ io.Reader) (err error) {
	log.Debug("Generating ElGamal key pair")
	priv.P = elgp
	priv.G = elgg

	// Generate cryptographically secure private key using secure random package
	// Private key must be in range [1, p-1]
	pMinus1 := new(big.Int).Sub(priv.P, one)

	// Use our secure random package for cryptographically secure key generation
	x, err := rand.ReadBigIntInRange(one, pMinus1)
	if err != nil {
		log.WithError(err).Error("Failed to generate secure private key")
		return oops.Errorf("ElGamal private key generation failed: %w", err)
	}

	priv.X = x

	// compute public key
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	log.Debug("ElGamal key pair generated successfully")
	return nil
}

// decrypt an elgamal encrypted message, i2p style
func elgamalDecrypt(priv *elgamal.PrivateKey, data []byte, zeroPadding bool) (decrypted []byte, err error) {
	log.WithFields(logrus.Fields{
		"data_length":  len(data),
		"zero_padding": zeroPadding,
	}).Debug("Decrypting ElGamal data")

	a := new(big.Int)
	b := new(big.Int)
	idx := 0
	if zeroPadding {
		idx++
	}
	a.SetBytes(data[idx : idx+256])
	if zeroPadding {
		idx++
	}
	b.SetBytes(data[idx+256:])

	// decrypt
	m := new(big.Int).Mod(new(big.Int).Mul(b, new(big.Int).Exp(a, new(big.Int).Sub(new(big.Int).Sub(priv.P, priv.X), one), priv.P)), priv.P).Bytes()

	// check digest
	d := sha256.Sum256(m[33:255])
	good := 0
	if subtle.ConstantTimeCompare(d[:], m[1:33]) == 1 {
		// decryption successful
		good = 1
		log.Debug("ElGamal decryption successful")
	} else {
		// decrypt failed
		err = ElgDecryptFail
		log.WithError(err).Error("ElGamal decryption failed")
	}
	// copy result
	decrypted = make([]byte, 222)
	subtle.ConstantTimeCopy(good, decrypted, m[33:255])

	if good == 0 {
		// if decrypt failed nil out decrypted slice
		decrypted = nil
	}
	return
}
