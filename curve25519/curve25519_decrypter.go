package curve25519

import (
	"crypto/sha256"
	"io"

	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Curve25519Decrypter handles Curve25519-based decryption operations.
// This type implements the types.Decrypter interface and provides X25519 elliptic curve
// decryption using ChaCha20-Poly1305 AEAD for secure data decryption in I2P network protocols.
type Curve25519Decrypter struct {
	privateKey x25519.PrivateKey // X25519 private key for ECDH key exchange and decryption
}

// Decrypt decrypts data that was encrypted using Curve25519 and ChaCha20-Poly1305 AEAD.
// The encrypted data format is: [ephemeral_public_key][nonce][aead_ciphertext]
// This method performs X25519 key exchange with the ephemeral public key, derives the decryption key
// using HKDF-SHA256, and then decrypts the data using ChaCha20-Poly1305 authenticated encryption.
// The minimum data size is 60 bytes (32-byte public key + 12-byte nonce + 16-byte tag).
func (c *Curve25519Decrypter) Decrypt(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Decrypting data with Curve25519")

	if err := c.validateDecryptionData(data); err != nil {
		return nil, err
	}

	sharedSecret, err := c.deriveSharedSecret(data)
	if err != nil {
		return nil, err
	}

	key, err := c.deriveDecryptionKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	plaintext, err := c.performAEADDecryption(data, key)
	if err != nil {
		return nil, err
	}

	log.Debug("Data decrypted successfully")
	return plaintext, nil
}

// validateDecryptionData validates that the encrypted data has sufficient length for decryption.
func (c *Curve25519Decrypter) validateDecryptionData(data []byte) error {
	minSize := x25519.PublicKeySize + 12 + 16 // 12 is ChaCha20-Poly1305 nonce size, 16 is tag size
	if len(data) < minSize {
		return oops.Errorf("data too short for Curve25519 decryption: %d bytes", len(data))
	}
	return nil
}

// deriveSharedSecret extracts the ephemeral public key and derives the shared secret.
func (c *Curve25519Decrypter) deriveSharedSecret(data []byte) ([]byte, error) {
	ephemeralPub := data[:x25519.PublicKeySize]

	var pubKey x25519.PublicKey
	copy(pubKey[:], ephemeralPub)

	sharedSecret, err := c.privateKey.SharedKey(pubKey[:])
	if err != nil {
		return nil, oops.Errorf("Curve25519 key exchange failed: %w", err)
	}

	return sharedSecret, nil
}

// deriveDecryptionKey derives the decryption key from the shared secret using HKDF-SHA256.
func (c *Curve25519Decrypter) deriveDecryptionKey(sharedSecret []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ChaCha20-Poly1305"))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, oops.Errorf("failed to derive decryption key: %w", err)
	}
	return key, nil
}

// performAEADDecryption creates the AEAD cipher and performs the actual decryption.
func (c *Curve25519Decrypter) performAEADDecryption(data []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(data) < x25519.PublicKeySize+nonceSize {
		return nil, oops.Errorf("data too short to extract nonce")
	}

	nonce := data[x25519.PublicKeySize : x25519.PublicKeySize+nonceSize]
	ciphertext := data[x25519.PublicKeySize+nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, oops.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}
