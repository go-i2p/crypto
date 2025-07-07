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
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Constants for ECIES-X25519 implementation
const (
	// PublicKeySize is the size of X25519 public keys in bytes
	PublicKeySize = 32
	// PrivateKeySize is the size of X25519 private keys in bytes
	PrivateKeySize = 32
	// NonceSize is the size of ChaCha20-Poly1305 nonces in bytes
	NonceSize = 12
	// TagSize is the size of Poly1305 authentication tags in bytes
	TagSize = 16
	// MaxPlaintextSize is the maximum size of plaintext data for encryption
	MaxPlaintextSize = 1024
)

// Error constants for ECIES operations
var (
	ErrInvalidPublicKey    = oops.Errorf("invalid public key for ECIES-X25519")
	ErrInvalidPrivateKey   = oops.Errorf("invalid private key for ECIES-X25519")
	ErrDataTooBig          = oops.Errorf("data too large for ECIES-X25519 encryption")
	ErrInvalidCiphertext   = oops.Errorf("invalid ciphertext for ECIES-X25519 decryption")
	ErrDecryptionFailed    = oops.Errorf("ECIES-X25519 decryption failed")
	ErrKeyDerivationFailed = oops.Errorf("ECIES-X25519 key derivation failed")
)

// EncryptECIESX25519 encrypts plaintext using ECIES-X25519 scheme.
// This implements the "New Session" message format from I2P Proposal 144.
// The recipient's public key must be 32 bytes (X25519 public key).
// Returns ciphertext in the format: [ephemeral_pubkey][nonce][aead_ciphertext]
func EncryptECIESX25519(recipientPubKey, plaintext []byte) ([]byte, error) {
	if len(recipientPubKey) != PublicKeySize {
		return nil, ErrInvalidPublicKey
	}

	if len(plaintext) > MaxPlaintextSize {
		return nil, ErrDataTooBig
	}

	// Generate ephemeral key pair using x25519 directly
	ephemeralPub, ephemeralPriv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate ephemeral key pair: %w", err)
	}

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

	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.New(encryptionKey)
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, oops.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext with associated data = ephemeral public key
	ciphertext := aead.Seal(nil, nonce, plaintext, ephemeralPub)

	// Build result: [ephemeral_pubkey][nonce][aead_ciphertext]
	result := make([]byte, PublicKeySize+NonceSize+len(ciphertext))
	offset := 0

	copy(result[offset:], ephemeralPub)
	offset += PublicKeySize

	copy(result[offset:], nonce)
	offset += NonceSize

	copy(result[offset:], ciphertext)

	return result, nil
}

// DecryptECIESX25519 decrypts ciphertext using ECIES-X25519 scheme.
// The private key must be 32 bytes (X25519 private key).
// The ciphertext must be in the format: [ephemeral_pubkey][nonce][aead_ciphertext]
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
