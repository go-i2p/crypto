package tunnel

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// log provides structured logging for tunnel cryptographic operations.
// This logger instance is configured for the go-i2p/crypto tunnel module and enables
// debugging of tunnel encryption/decryption processes, layer key operations, and error tracking.
// Logger instance for Tunnel package operations
// Moved from: tunnel.go
var log = logger.GetGoI2PLogger()

// Error definitions for tunnel cryptographic operations using structured error handling.
// These errors follow the oops pattern for consistent error wrapping and context preservation.
var (
	// ErrInvalidKeySize indicates that a provided key does not meet the required size.
	// AES-256 requires exactly 32-byte keys for both layer and IV encryption.
	ErrInvalidKeySize = oops.Errorf("invalid key size: must be 32 bytes for AES-256")

	// ErrCipherCreationFailed indicates that AES cipher initialization failed.
	// This typically occurs due to invalid key material or system-level cryptographic failures.
	ErrCipherCreationFailed = oops.Errorf("failed to create AES cipher block")

	// ErrNilTunnelData indicates that a nil TunnelData pointer was passed to encryption/decryption.
	// All tunnel operations require valid non-nil TunnelData structures.
	ErrNilTunnelData = oops.Errorf("tunnel data cannot be nil")

	// ErrEncryptionFailed indicates that the encryption operation failed.
	// This may occur due to invalid data, corrupted keys, or cryptographic processing errors.
	ErrEncryptionFailed = oops.Errorf("tunnel encryption failed")

	// ErrDecryptionFailed indicates that the decryption operation failed.
	// This may occur due to invalid ciphertext, incorrect keys, or authentication failures.
	ErrDecryptionFailed = oops.Errorf("tunnel decryption failed")

	// ErrUnsupportedEncryptionType indicates an unsupported tunnel encryption scheme was requested.
	// Only TunnelEncryptionAES (0) and TunnelEncryptionECIES (1) are supported.
	ErrUnsupportedEncryptionType = oops.Errorf("unsupported tunnel encryption type")

	// ECIES-specific error constants for structured error handling

	// ErrECIESEncryptionFailed indicates that ECIES encryption operation failed.
	// This may occur due to invalid public keys, data size limits, or underlying cryptographic errors.
	ErrECIESEncryptionFailed = oops.Errorf("ECIES encryption failed")

	// ErrECIESDecryptionFailed indicates that ECIES decryption operation failed.
	// This may occur due to invalid private keys, corrupted ciphertext, or authentication failures.
	ErrECIESDecryptionFailed = oops.Errorf("ECIES decryption failed")

	// ErrECIESInvalidPublicKey indicates that an invalid X25519 public key was provided for ECIES encryption.
	// ECIES public keys must be exactly 32 bytes and contain valid curve points.
	ErrECIESInvalidPublicKey = oops.Errorf("invalid X25519 public key for ECIES encryption")

	// ErrECIESInvalidPrivateKey indicates that an invalid X25519 private key was provided for ECIES decryption.
	// ECIES private keys must be exactly 32 bytes and within the valid scalar range.
	ErrECIESInvalidPrivateKey = oops.Errorf("invalid X25519 private key for ECIES decryption")

	// ErrECIESInvalidCiphertext indicates that ECIES ciphertext has invalid format or size.
	// ECIES ciphertext must include ephemeral public key, nonce, and authenticated encryption tag.
	ErrECIESInvalidCiphertext = oops.Errorf("invalid ECIES ciphertext format")

	// ErrECIESOperationNotSupported indicates that an unsupported operation was attempted.
	// For example, trying to decrypt with an encryptor or encrypt with a decryptor.
	ErrECIESOperationNotSupported = oops.Errorf("ECIES operation not supported by this instance")
)
