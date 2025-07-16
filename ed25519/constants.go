package ed25519

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// log provides the logger instance for Ed25519 package operations and debugging.
// Logger instance for Ed25519 package operations
// Moved from: ed25519.go
var log = logger.GetGoI2PLogger()

// ErrInvalidPublicKeySize indicates an Ed25519 public key does not meet the required 32-byte size.
// Error constants for Ed25519 operations
// Moved from: ed25519.go
var (
	ErrInvalidPublicKeySize = oops.Errorf("failed to verify: invalid ed25519 public key size")
)
