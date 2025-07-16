package elg

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

// PrivateKey wraps the standard ElGamal private key with I2P-specific functionality.
// Provides compatibility layer between I2P's ElGamal implementation and the underlying cryptographic library.
type PrivateKey struct {
	elgamal.PrivateKey
}

// ElgamalGenerate creates a new ElGamal key pair using I2P's standard parameters.
// Generates cryptographically secure private keys in the range [1, p-1] using the secure random package.
// The io.Reader parameter is ignored as we use our own secure random source for enhanced security.
// generate an elgamal key pair
func ElgamalGenerate(priv *elgamal.PrivateKey, _ io.Reader) (err error) {
	log.Debug("Generating ElGamal key pair")
	// Set standard I2P ElGamal parameters
	// Use the fixed prime p and generator g for compatibility
	priv.P = elgp
	priv.G = elgg

	// Generate cryptographically secure private key using secure random package
	// Private key must be in range [1, p-1] for ElGamal security
	pMinus1 := new(big.Int).Sub(priv.P, one)

	// Use our secure random package for cryptographically secure key generation
	x, err := rand.ReadBigIntInRange(one, pMinus1)
	if err != nil {
		log.WithError(err).Error("Failed to generate secure private key")
		return oops.Errorf("ElGamal private key generation failed: %w", err)
	}

	priv.X = x

	// Compute public key y = g^x mod p
	// This derives the public component from the private exponent
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	log.Debug("ElGamal key pair generated successfully")
	return nil
}

// elgamalDecrypt decrypts ElGamal encrypted data using I2P's specific format and validation.
// Implements constant-time operations to prevent timing attacks during decryption.
// The zeroPadding parameter controls parsing of the encrypted data format.
// decrypt an elgamal encrypted message, i2p style
func elgamalDecrypt(priv *elgamal.PrivateKey, data []byte, zeroPadding bool) (decrypted []byte, err error) {
	log.WithFields(logrus.Fields{
		"data_length":  len(data),
		"zero_padding": zeroPadding,
	}).Debug("Decrypting ElGamal data")

	// Extract ElGamal ciphertext components (a, b) from encrypted data
	// Parse according to I2P's ElGamal message format with optional padding
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

	// Perform ElGamal decryption: m = b * a^(-x) mod p
	// Uses modular arithmetic to recover the original message
	m := new(big.Int).Mod(new(big.Int).Mul(b, new(big.Int).Exp(a, new(big.Int).Sub(new(big.Int).Sub(priv.P, priv.X), one), priv.P)), priv.P).Bytes()

	// Verify message integrity using SHA-256 digest
	// Constant-time comparison prevents timing attacks during validation
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
	// Copy result using constant-time operation to prevent side-channel attacks
	decrypted = make([]byte, 222)
	subtle.ConstantTimeCopy(good, decrypted, m[33:255])

	if good == 0 {
		// if decrypt failed nil out decrypted slice
		decrypted = nil
	}
	return
}
