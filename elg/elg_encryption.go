package elg

import (
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp/elgamal"
)

// ElgamalEncryption represents an ElGamal encryption session with precomputed parameters.
// It stores the necessary cryptographic parameters (p, a, b1) for efficient encryption operations.
// Multiple messages can be encrypted using the same session for performance optimization.
type ElgamalEncryption struct {
	p, a, b1 *big.Int
}

// Encrypt encrypts data using ElGamal with zero padding enabled by default.
// Provides a simple interface for standard ElGamal encryption operations.
// Returns encrypted data or error if encryption fails or data is too large (>222 bytes).
func (elg *ElgamalEncryption) Encrypt(data []byte) (enc []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Encrypting data with ElGamal")
	return elg.EncryptPadding(data, true)
}

// EncryptPadding encrypts data using ElGamal with configurable padding options.
// The zeroPadding parameter controls whether to apply zero-padding for data shorter than block size.
// Maximum supported data size is 222 bytes due to ElGamal security requirements.
func (elg *ElgamalEncryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error) {
	log.WithFields(logrus.Fields{
		"data_length":  len(data),
		"zero_padding": zeroPadding,
	}).Debug("Encrypting data with ElGamal padding")

	// Validate data size limit for ElGamal security
	// ElGamal can only encrypt data smaller than the modulus
	if len(data) > 222 {
		err = ElgEncryptTooBig
		return
	}
	mbytes := make([]byte, 255)
	mbytes[0] = 0xFF
	copy(mbytes[33:], data)
	// do sha256 of payload
	d := sha256.Sum256(mbytes[33 : len(data)+33])
	copy(mbytes[1:], d[:])
	m := new(big.Int).SetBytes(mbytes)
	// do encryption
	// Compute ElGamal ciphertext components: a = g^k mod p, b = m * y^k mod p
	// This implements the standard ElGamal encryption algorithm
	b := new(big.Int).Mod(new(big.Int).Mul(elg.b1, m), elg.p).Bytes()

	// Format output according to I2P ElGamal message structure
	// Zero padding adds extra bytes for protocol compatibility
	if zeroPadding {
		encrypted = make([]byte, 514)
		copy(encrypted[1:], elg.a.Bytes())
		copy(encrypted[258:], b)
	} else {
		encrypted = make([]byte, 512)
		copy(encrypted, elg.a.Bytes())
		copy(encrypted[256:], b)
	}

	log.WithField("encrypted_length", len(encrypted)).Debug("Data encrypted successfully with ElGamal")
	return
}

// createElgamalEncryption initializes a new ElGamal encryption session with precomputed parameters.
// Generates a random ephemeral key k and precomputes a = g^k mod p and b1 = y^k mod p for efficiency.
// Multiple encryptions can reuse these parameters for better performance.
// create a new elgamal encryption session
func createElgamalEncryption(pub *elgamal.PublicKey, rand io.Reader) (enc *ElgamalEncryption, err error) {
	log.Debug("Creating ElGamal encryption session")
	// Generate cryptographically secure ephemeral key k
	// Must be non-zero and less than the prime modulus p
	kbytes := make([]byte, 256)
	k := new(big.Int)
	for err == nil {
		_, err = io.ReadFull(rand, kbytes)
		k = new(big.Int).SetBytes(kbytes)
		k = k.Mod(k, pub.P)
		// Ensure k is not zero for cryptographic security
		if k.Sign() != 0 {
			break
		}
	}
	if err == nil {
		enc = &ElgamalEncryption{
			p:  pub.P,
			a:  new(big.Int).Exp(pub.G, k, pub.P),
			b1: new(big.Int).Exp(pub.Y, k, pub.P),
		}
		log.Debug("ElGamal encryption session created successfully")
	} else {
		log.WithError(err).Error("Failed to create ElGamal encryption session")
	}
	return
}
