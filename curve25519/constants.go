package curve25519

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Logger instance for Curve25519 package operations
// Moved from: curve25519.go
var log = logger.GetGoI2PLogger()

// Error constants for Curve25519 operations
// Moved from: curve25519.go
var (
	ErrDataTooBig        = oops.Errorf("data too big for Curve25519 encryption")
	ErrInvalidPublicKey  = oops.Errorf("invalid public key for Curve25519")
	ErrInvalidPrivateKey = oops.Errorf("invalid private key for Curve25519")
	ErrInvalidSignature  = oops.Errorf("invalid signature for Curve25519")
	ErrDecryptionFailed  = oops.Errorf("failed to decrypt data with Curve25519")
)
