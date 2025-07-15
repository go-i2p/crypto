package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type RSA4096PrivateKey struct {
	RSA4096PrivateKey [1024]byte // I2P-compliant: 512 bytes modulus + 512 bytes private exponent
}

// Sign implements types.Signer.
// Signs data by first hashing it with SHA-512
func (r RSA4096PrivateKey) Sign(data []byte) (sig []byte, err error) {
	log.Debug("Signing data with RSA-4096")
	// Hash the data with SHA-512 (appropriate for RSA-4096)
	hash := sha512.Sum512(data)
	return r.SignHash(hash[:])
}

// SignHash implements types.Signer.
// Signs a pre-computed hash
func (r RSA4096PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	log.Debug("Signing hash with RSA-4096")

	// Convert I2P format to rsa.PrivateKey
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		log.WithError(err).Error("Failed to parse RSA-4096 private key")
		return nil, oops.Errorf("invalid RSA-4096 private key: %w", err)
	}

	// Sign the hash using PKCS1v15
	sig, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, h)
	if err != nil {
		log.WithError(err).Error("RSA-4096 signature generation failed")
		return nil, oops.Errorf("failed to generate RSA-4096 signature: %w", err)
	}

	log.Debug("RSA-4096 signature generated successfully")
	return sig, nil
}

// Bytes implements types.PrivateKey.
// Returns the raw bytes of the private key
func (r RSA4096PrivateKey) Bytes() []byte {
	log.Debug("Getting RSA-4096 private key bytes")
	return r.RSA4096PrivateKey[:]
}

// Public implements types.PrivateKey.
// Extracts the public key from the private key
func (r RSA4096PrivateKey) Public() (types.SigningPublicKey, error) {
	log.Debug("Extracting public key from RSA-4096 private key")

	// Convert I2P format to rsa.PrivateKey
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		log.WithError(err).Error("Failed to parse RSA-4096 private key")
		return nil, oops.Errorf("invalid RSA-4096 private key: %w", err)
	}

	// Get the public key bytes (modulus n) in the correct format
	pubKeyBytes := privKey.N.Bytes()

	// The RSA4096PublicKey is exactly 512 bytes
	var pubKey RSA4096PublicKey

	// Ensure proper padding if the modulus has leading zeros
	copy(pubKey[512-len(pubKeyBytes):], pubKeyBytes)

	log.Debug("RSA-4096 public key extracted successfully")
	return pubKey, nil
}

// Helper method to convert I2P format to rsa.PrivateKey
func (r RSA4096PrivateKey) toRSAPrivateKey() (*rsa.PrivateKey, error) {
	// Extract modulus (N) from first 512 bytes
	nBytes := r.RSA4096PrivateKey[:512]
	n := new(big.Int).SetBytes(nBytes)

	// Extract private exponent (D) from next 512 bytes
	dBytes := r.RSA4096PrivateKey[512:1024]
	d := new(big.Int).SetBytes(dBytes)

	// Standard RSA public exponent
	e := 65537

	// Create RSA private key
	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: e,
		},
		D: d,
	}

	// Validate key size is 4096 bits
	if privKey.Size() != 512 {
		return nil, oops.Errorf("unexpected RSA key size: got %d, want 512", privKey.Size())
	}

	return privKey, nil
}

// Zero implements types.PrivateKey.
// Securely clears the private key from memory
func (r *RSA4096PrivateKey) Zero() {
	log.Debug("Securely clearing RSA-4096 private key from memory")
	// Overwrite the key material with zeros
	for i := range r.RSA4096PrivateKey {
		r.RSA4096PrivateKey[i] = 0
	}
}

var (
	_ types.PrivateKey = (*RSA4096PrivateKey)(nil)
	_ types.Signer     = RSA4096PrivateKey{}
)
