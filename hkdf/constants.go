package hkdf

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// Common HKDF errors
var (
	ErrInvalidKeyLength    = oops.Errorf("invalid key length")
	ErrInvalidSaltLength   = oops.Errorf("invalid salt length")
	ErrInvalidInfoLength   = oops.Errorf("invalid info length")
	ErrKeyDerivationFailed = oops.Errorf("key derivation failed")
)

// Default parameters for I2P compatibility
const (
	DefaultKeyLength = 32  // 256 bits for ChaCha20
	MaxInfoLength    = 255 // Maximum info length for HKDF
)
