package chacha20poly1305

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

const (
	// KeySize is the size of the ChaCha20-Poly1305 key in bytes (256 bits)
	KeySize = 32

	// NonceSize is the size of the nonce in bytes for ChaCha20-Poly1305
	// Standard IETF ChaCha20-Poly1305 uses 12-byte nonces
	NonceSize = 12

	// TagSize is the size of the Poly1305 authentication tag in bytes (128 bits)
	TagSize = 16
)

// Common errors for ChaCha20-Poly1305 AEAD operations
var (
	// ErrInvalidKeySize indicates the key is not 32 bytes
	ErrInvalidKeySize = oops.Errorf("invalid ChaCha20-Poly1305 key size: must be 32 bytes")

	// ErrInvalidNonceSize indicates the nonce is not 12 bytes
	ErrInvalidNonceSize = oops.Errorf("invalid ChaCha20-Poly1305 nonce size: must be 12 bytes")

	// ErrAuthenticationFailed indicates Poly1305 tag verification failed
	ErrAuthenticationFailed = oops.Errorf("ChaCha20-Poly1305 authentication failed: message has been tampered with")

	// ErrInvalidCiphertext indicates the ciphertext format is invalid
	ErrInvalidCiphertext = oops.Errorf("invalid ciphertext: too short or malformed")
)

// Package-level logger instance for ChaCha20-Poly1305 AEAD operations
var log = logger.GetGoI2PLogger()
