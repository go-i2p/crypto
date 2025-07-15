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
	if err := validateDecryptionInputs(recipientPrivKey, ciphertext); err != nil {
		return nil, err
	}

	ephemeralPubKey, nonce, aeadCiphertext := extractCiphertextComponents(ciphertext)

	privKey, ephemeralKey := convertKeysToX25519Format(recipientPrivKey, ephemeralPubKey)

	decryptionKey, err := performKeyAgreementAndDerivation(privKey, ephemeralKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptWithAEAD(decryptionKey, nonce, aeadCiphertext, ephemeralPubKey)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// validateDecryptionInputs checks that the private key and ciphertext are valid for decryption.
func validateDecryptionInputs(recipientPrivKey, ciphertext []byte) error {
	if len(recipientPrivKey) != PrivateKeySize {
		return ErrInvalidPrivateKey
	}

	minSize := PublicKeySize + NonceSize + TagSize
	if len(ciphertext) < minSize {
		return ErrInvalidCiphertext
	}

	return nil
}

// extractCiphertextComponents parses the ciphertext format and extracts its components.
func extractCiphertextComponents(ciphertext []byte) (ephemeralPubKey, nonce, aeadCiphertext []byte) {
	ephemeralPubKey = ciphertext[:PublicKeySize]
	nonce = ciphertext[PublicKeySize : PublicKeySize+NonceSize]
	aeadCiphertext = ciphertext[PublicKeySize+NonceSize:]
	return
}

// convertKeysToX25519Format converts raw byte keys to proper X25519 key types.
func convertKeysToX25519Format(recipientPrivKey, ephemeralPubKey []byte) (x25519.PrivateKey, x25519.PublicKey) {
	privKey := x25519.PrivateKey(recipientPrivKey)
	ephemeralKey := x25519.PublicKey(ephemeralPubKey)
	return privKey, ephemeralKey
}

// performKeyAgreementAndDerivation executes X25519 key agreement and derives the decryption key.
func performKeyAgreementAndDerivation(privKey x25519.PrivateKey, ephemeralKey x25519.PublicKey) ([]byte, error) {
	sharedSecret, err := privKey.SharedKey(ephemeralKey)
	if err != nil {
		return nil, oops.Errorf("X25519 key agreement failed: %w", err)
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ECIES-X25519-AEAD"))
	decryptionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, decryptionKey); err != nil {
		return nil, oops.Errorf("HKDF key derivation failed: %w", err)
	}

	return decryptionKey, nil
}

// decryptWithAEAD creates an AEAD cipher and performs the final decryption step.
func decryptWithAEAD(decryptionKey, nonce, aeadCiphertext, ephemeralPubKey []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(decryptionKey)
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

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
