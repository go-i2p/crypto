package chacha20

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Logger instance for ChaCha20 package operations
// Moved from: chacha20.go
var log = logger.GetGoI2PLogger()

// Key and nonce size constants for ChaCha20
// Moved from: chacha20.go
const (
	KeySize   = 32
	NonceSize = 12 // ChaCha20-Poly1305 standard nonce size
	TagSize   = 16 // Poly1305 authentication tag size
)

// Error constants for ChaCha20 operations
// Moved from: chacha20.go
var (
	ErrInvalidKeySize   = oops.Errorf("invalid ChaCha20 key size")
	ErrInvalidNonceSize = oops.Errorf("invalid ChaCha20 nonce size")
	ErrEncryptFailed    = oops.Errorf("ChaCha20 encryption failed")
	ErrDecryptFailed    = oops.Errorf("ChaCha20 decryption failed")
	ErrAuthFailed       = oops.Errorf("ChaCha20-Poly1305 authentication failed")
)
