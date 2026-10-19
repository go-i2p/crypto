package rand

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// package-level logger instance
var log = logger.GetGoI2PLogger()

// Common errors for random number generation
var (
	ErrInsufficientEntropy = oops.Errorf("insufficient entropy in random source")
	ErrRandomReadFailed    = oops.Errorf("failed to read from random source")
	ErrEntropyValidation   = oops.Errorf("entropy validation failed")
)

// Entropy validation constants
const (
	// Minimum entropy threshold for random data (bits per byte)
	// Reduced to 4.0 for crypto/rand compatibility while still catching patterns
	MinEntropyThreshold = 4.0

	// MaxEntropyRetries bounds the rejection loop in SecureReader.ReadBigInt,
	// which regenerates until the value falls in [0, max). It no longer applies
	// to SecureReader.Read, whose entropy check is advisory (log-only) rather
	// than a retry-and-fail gate.
	MaxEntropyRetries = 10
)
