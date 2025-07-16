package curve25519

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// log provides structured logging for Curve25519 package operations.
// This logger instance is configured for the go-i2p/crypto Curve25519 module and enables
// debugging of cryptographic operations, key management, and error tracking.
var log = logger.GetGoI2PLogger()

// Error constants for Curve25519 cryptographic operations.
// These errors provide specific failure modes for X25519 elliptic curve operations
// including encryption, decryption, signing, verification, and key management.
var (
	// ErrDataTooBig indicates that input data exceeds the maximum size for Curve25519 encryption.
	// The maximum allowed size is 1024 bytes to support I2P tunnel build records and protocol requirements.
	ErrDataTooBig = oops.Errorf("data too big for Curve25519 encryption")

	// ErrInvalidPublicKey indicates that a Curve25519 public key has invalid format or size.
	// Valid X25519 public keys must be exactly 32 bytes in length and contain valid curve points.
	ErrInvalidPublicKey = oops.Errorf("invalid public key for Curve25519")

	// ErrInvalidPrivateKey indicates that a Curve25519 private key has invalid format or size.
	// Valid X25519 private keys must be exactly 32 bytes and within the valid scalar range.
	ErrInvalidPrivateKey = oops.Errorf("invalid private key for Curve25519")

	// ErrInvalidSignature indicates that a Curve25519 signature verification failed.
	// This occurs when the signature doesn't match the expected format or fails cryptographic verification.
	ErrInvalidSignature = oops.Errorf("invalid signature for Curve25519")

	// ErrDecryptionFailed indicates that Curve25519 decryption operation failed.
	// This typically occurs due to corrupted ciphertext, wrong keys, or invalid data format.
	ErrDecryptionFailed = oops.Errorf("failed to decrypt data with Curve25519")
)
