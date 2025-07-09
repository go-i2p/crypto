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
	ErrInvalidKeySize     = oops.Errorf("invalid RSA key size")
	ErrInvalidKeyFormat   = oops.Errorf("invalid RSA key format")
	ErrSignatureFailed    = oops.Errorf("RSA signature operation failed")
	ErrVerificationFailed = oops.Errorf("RSA signature verification failed")
)
