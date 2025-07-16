package rsa

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Logger instance for RSA package operations
// Moved from: rsa.go
var log = logger.GetGoI2PLogger()

// Error constants for RSA operations
var (
	// ErrInvalidKeySize indicates that the provided RSA key size is not supported or valid.
	// Valid RSA key sizes in I2P are 2048, 3072, and 4096 bits.
	ErrInvalidKeySize = oops.Errorf("invalid RSA key size")

	// ErrInvalidKeyFormat indicates that the RSA key data is malformed or corrupted.
	// RSA keys must follow I2P's standard byte array format for proper parsing.
	ErrInvalidKeyFormat = oops.Errorf("invalid RSA key format")

	// ErrSignatureFailed indicates that the RSA signature generation operation failed.
	// This can occur due to invalid keys, insufficient entropy, or cryptographic errors.
	ErrSignatureFailed = oops.Errorf("RSA signature operation failed")

	// ErrVerificationFailed indicates that RSA signature verification failed.
	// This occurs when a signature does not match the provided data and public key.
	ErrVerificationFailed = oops.Errorf("RSA signature verification failed")
)
