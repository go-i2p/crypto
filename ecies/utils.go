// Package ecies utility functions for ECIES-X25519-AEAD-Ratchet encryption.
// Moved from: ecies.go
package ecies

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// EncryptECIESX25519 encrypts plaintext using ECIES-X25519 scheme.
// This implements the "New Session" message format from I2P Proposal 144.
// The recipient's public key must be 32 bytes (X25519 public key).
// Returns ciphertext in the format: [ephemeral_pubkey][nonce][aead_ciphertext]
// Moved from: ecies.go
func EncryptECIESX25519(recipientPubKey, plaintext []byte) ([]byte, error) {
	if err := validateEncryptionInputs(recipientPubKey, plaintext); err != nil {
		return nil, err
	}

	ephemeralPub, ephemeralPriv, err := generateEphemeralKeyPair()
	if err != nil {
		return nil, err
	}

	encryptionKey, err := deriveEncryptionKey(ephemeralPriv, recipientPubKey)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext, err := encryptWithAEAD(encryptionKey, plaintext, ephemeralPub)
	if err != nil {
		return nil, err
	}

	result := buildCiphertextResult(ephemeralPub, nonce, ciphertext)
	return result, nil
}

// validateEncryptionInputs checks that the recipient public key and plaintext are valid.
func validateEncryptionInputs(recipientPubKey, plaintext []byte) error {
	if len(recipientPubKey) != PublicKeySize {
		return ErrInvalidPublicKey
	}

	if len(plaintext) > MaxPlaintextSize {
		return ErrDataTooBig
	}

	return nil
}

// generateEphemeralKeyPair creates a new ephemeral X25519 key pair for encryption.
func generateEphemeralKeyPair() ([]byte, x25519.PrivateKey, error) {
	ephemeralPub, ephemeralPriv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, oops.Errorf("failed to generate ephemeral key pair: %w", err)
	}

	return ephemeralPub, ephemeralPriv, nil
}

// deriveEncryptionKey performs X25519 key agreement and derives the encryption key using HKDF.
func deriveEncryptionKey(ephemeralPriv x25519.PrivateKey, recipientPubKey []byte) ([]byte, error) {
	// Convert recipient public key to x25519 format
	recipientKey := x25519.PublicKey(recipientPubKey)

	// Perform X25519 key agreement (ephemeral-static DH)
	sharedSecret, err := ephemeralPriv.SharedKey(recipientKey)
	if err != nil {
		return nil, oops.Errorf("X25519 key agreement failed: %w", err)
	}

	// Derive encryption key using HKDF with SHA-256
	// This follows the KDF pattern from I2P Proposal 144
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ECIES-X25519-AEAD"))
	encryptionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, encryptionKey); err != nil {
		return nil, oops.Errorf("HKDF key derivation failed: %w", err)
	}

	return encryptionKey, nil
}

// encryptWithAEAD encrypts the plaintext using ChaCha20-Poly1305 AEAD with a random nonce.
func encryptWithAEAD(encryptionKey, plaintext, ephemeralPub []byte) ([]byte, []byte, error) {
	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.New(encryptionKey)
	if err != nil {
		return nil, nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, oops.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext with associated data = ephemeral public key
	ciphertext := aead.Seal(nil, nonce, plaintext, ephemeralPub)

	return nonce, ciphertext, nil
}

// buildCiphertextResult assembles the final ciphertext in the format [ephemeral_pubkey][nonce][aead_ciphertext].
func buildCiphertextResult(ephemeralPub, nonce, ciphertext []byte) []byte {
	result := make([]byte, PublicKeySize+NonceSize+len(ciphertext))
	offset := 0

	copy(result[offset:], ephemeralPub)
	offset += PublicKeySize

	copy(result[offset:], nonce)
	offset += NonceSize

	copy(result[offset:], ciphertext)

	return result
}

// DecryptECIESX25519 decrypts ciphertext using ECIES-X25519 scheme.
// The private key must be 32 bytes (X25519 private key).
// The ciphertext must be in the format: [ephemeral_pubkey][nonce][aead_ciphertext]
// Moved from: ecies.go
func DecryptECIESX25519(recipientPrivKey, ciphertext []byte) ([]byte, error) {
	if len(recipientPrivKey) != PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}

	// Validate minimum ciphertext length
	minSize := PublicKeySize + NonceSize + TagSize
	if len(ciphertext) < minSize {
		return nil, ErrInvalidCiphertext
	}

	// Extract components from ciphertext
	ephemeralPubKey := ciphertext[:PublicKeySize]
	nonce := ciphertext[PublicKeySize : PublicKeySize+NonceSize]
	aeadCiphertext := ciphertext[PublicKeySize+NonceSize:]

	// Convert private key to proper format
	privKey := x25519.PrivateKey(recipientPrivKey)

	// Convert ephemeral public key to proper format
	ephemeralKey := x25519.PublicKey(ephemeralPubKey)

	// Perform X25519 key agreement (static-ephemeral DH)
	sharedSecret, err := privKey.SharedKey(ephemeralKey)
	if err != nil {
		return nil, oops.Errorf("X25519 key agreement failed: %w", err)
	}

	// Derive decryption key using HKDF with SHA-256
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ECIES-X25519-AEAD"))
	decryptionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, decryptionKey); err != nil {
		return nil, oops.Errorf("HKDF key derivation failed: %w", err)
	}

	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.New(decryptionKey)
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Decrypt ciphertext with associated data = ephemeral public key
	plaintext, err := aead.Open(nil, nonce, aeadCiphertext, ephemeralPubKey)
	if err != nil {
		return nil, oops.Errorf("ChaCha20-Poly1305 decryption failed: %w", err)
	}

	return plaintext, nil
}

// GenerateKeyPair generates a new X25519 key pair suitable for ECIES-X25519.
// Returns (publicKey, privateKey, error) where keys are 32 bytes each.
// Moved from: ecies.go
func GenerateKeyPair() ([]byte, []byte, error) {
	pub, priv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, oops.Errorf("failed to generate X25519 key pair: %w", err)
	}

	// Return copies to prevent external modification
	pubKey := make([]byte, PublicKeySize)
	privKey := make([]byte, PrivateKeySize)
	copy(pubKey, pub[:])
	copy(privKey, priv[:])

	return pubKey, privKey, nil
}
