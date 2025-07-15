// Package ecies constants for ECIES-X25519-AEAD-Ratchet encryption.
// Moved from: ecies.go
package ecies

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Logger instance for ECIES package operations
var log = logger.GetGoI2PLogger()

// Constants for ECIES-X25519 implementation
// Moved from: ecies.go
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
// Moved from: ecies.go
var (
	ErrInvalidPublicKey    = oops.Errorf("invalid public key for ECIES-X25519")
	ErrInvalidPrivateKey   = oops.Errorf("invalid private key for ECIES-X25519")
	ErrDataTooBig          = oops.Errorf("data too large for ECIES-X25519 encryption")
	ErrInvalidCiphertext   = oops.Errorf("invalid ciphertext for ECIES-X25519 decryption")
	ErrDecryptionFailed    = oops.Errorf("ECIES-X25519 decryption failed")
	ErrKeyDerivationFailed = oops.Errorf("ECIES-X25519 key derivation failed")
)
