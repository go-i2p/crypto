package aes

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Logger instance for AES package operations
// Moved from: aes_decrypter.go
var log = logger.GetGoI2PLogger()

// Error definitions for AES operations
var (
	// ErrInvalidKeySize indicates the AES key is not 16, 24, or 32 bytes
	ErrInvalidKeySize = oops.Errorf("invalid AES key size: must be 16, 24, or 32 bytes")

	// ErrInvalidIVSize indicates the AES IV is not 16 bytes
	ErrInvalidIVSize = oops.Errorf("invalid AES IV size: must be 16 bytes")
)
