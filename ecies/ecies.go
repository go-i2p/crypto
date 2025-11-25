// Package ecies implements ECIES-X25519-AEAD-Ratchet encryption as specified in I2P Proposal 144.
//
// This package provides the modern I2P encryption scheme that replaces ElGamal/AES+SessionTags.
// It implements ephemeral-static and ephemeral-ephemeral Diffie-Hellman key agreement
// using X25519, combined with ChaCha20-Poly1305 AEAD encryption.
//
// The implementation follows I2P Proposal 144 specification:
// https://geti2p.net/spec/proposals/144-ecies-x25519-aead-ratchet
package ecies

import (
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

// ECIESPublicKey represents an ECIES X25519 public key for encryption
type ECIESPublicKey [PublicKeySize]byte

// ECIESPrivateKey represents an ECIES X25519 private key for decryption
type ECIESPrivateKey [PrivateKeySize]byte

// Len returns the length of the public key in bytes
func (k ECIESPublicKey) Len() int {
	return len(k)
}

// Bytes returns the public key as a byte slice
func (k ECIESPublicKey) Bytes() []byte {
	return k[:]
}

// NewEncrypter creates a new encrypter using this public key
func (k ECIESPublicKey) NewEncrypter() (types.Encrypter, error) {
	return &ECIESEncrypter{PublicKey: k}, nil
}

// Len returns the length of the private key in bytes
func (k ECIESPrivateKey) Len() int {
	return len(k)
}

// Bytes returns the private key as a byte slice
func (k ECIESPrivateKey) Bytes() []byte {
	return k[:]
}

// NewDecrypter creates a new decrypter using this private key
func (k ECIESPrivateKey) NewDecrypter() (types.Decrypter, error) {
	return &ECIESDecrypter{PrivateKey: k}, nil
}

// Public returns the corresponding public key derived from this private key.
// This uses X25519 scalar base multiplication to properly derive the public key.
func (k ECIESPrivateKey) Public() (types.PublicEncryptionKey, error) {
	// Convert to X25519 private key format
	privKey := x25519.PrivateKey(k[:])

	// Derive public key using X25519 scalar base multiplication
	pubKeyInterface := privKey.Public()

	// Type assert to get the actual public key bytes
	pubKeyBytes, ok := pubKeyInterface.(x25519.PublicKey)
	if !ok {
		log.Error("Failed to type assert X25519 public key")
		return nil, oops.Errorf("failed to derive public key from private key")
	}

	// Copy to ECIESPublicKey
	var pubKey ECIESPublicKey
	copy(pubKey[:], pubKeyBytes)

	log.Debug("ECIES public key derived successfully from private key")
	return pubKey, nil
}

// Zero securely clears the private key from memory
func (k ECIESPrivateKey) Zero() {
	for i := range k {
		k[i] = 0
	}
}

// ECIESEncrypter implements types.Encrypter using ECIES
type ECIESEncrypter struct {
	PublicKey ECIESPublicKey
}

// Encrypt encrypts data using ECIES-X25519
func (e *ECIESEncrypter) Encrypt(data []byte) ([]byte, error) {
	return EncryptECIESX25519(e.PublicKey[:], data)
}

// ECIESDecrypter implements types.Decrypter using ECIES
type ECIESDecrypter struct {
	PrivateKey ECIESPrivateKey
}

// Decrypt decrypts data using ECIES-X25519
func (d *ECIESDecrypter) Decrypt(data []byte) ([]byte, error) {
	return DecryptECIESX25519(d.PrivateKey[:], data)
}

// GenerateECIESKeyPair generates a new ECIES key pair using the standard interface types
func GenerateECIESKeyPair() (*ECIESPublicKey, *ECIESPrivateKey, error) {
	log.Debug("Generating ECIES key pair")

	pubBytes, privBytes, err := GenerateKeyPair()
	if err != nil {
		log.WithError(err).Error("Failed to generate ECIES key pair")
		return nil, nil, err
	}

	var pubKey ECIESPublicKey
	var privKey ECIESPrivateKey

	copy(pubKey[:], pubBytes)
	copy(privKey[:], privBytes)

	log.Debug("ECIES key pair generated successfully")
	return &pubKey, &privKey, nil
}
