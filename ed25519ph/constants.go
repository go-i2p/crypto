package ed25519ph

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// log provides the logger instance for Ed25519ph package operations and debugging.
var log = logger.GetGoI2PLogger()

// Error constants for Ed25519ph operations.
var (
	// ErrInvalidPublicKeySize indicates an Ed25519 public key does not meet the required 32-byte size.
	ErrInvalidPublicKeySize = oops.Errorf("failed to verify: invalid ed25519ph public key size")

	// ErrInvalidPrivateKeySize indicates an Ed25519 private key does not meet the required 64-byte size.
	ErrInvalidPrivateKeySize = oops.Errorf("invalid ed25519ph private key size")
)
