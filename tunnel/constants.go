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

// Tunnel message field offsets and sizes, per the Tunnel Message specification
// (https://i2p.net/en/docs/specs/tunnel-message/, section "Tunnel Message
// (Encrypted)"):
//
//	bytes 0..3     Tunnel ID        4 bytes, cleartext, nonzero
//	bytes 4..19    IV               16 bytes
//	bytes 20..1027 Encrypted Data   1008 bytes
//	Total size: 1028 bytes
//
// The AES layer cipher processes bytes 4..19 (the IV, transformed with the IV
// key) and bytes 20..1027 (the payload, CBC with the layer key). The 4-byte
// tunnel ID is caller framing and is never touched by the cipher.
const (
	// TunnelMessageSize is the fixed size of a tunnel message block.
	TunnelMessageSize = 1028
	// TunnelIDSize is the size of the cleartext tunnel ID at the head of the block.
	TunnelIDSize = 4
	// TunnelIVOffset is the byte offset of the 16-byte initialization vector.
	TunnelIVOffset = TunnelIDSize // 4
	// TunnelIVSize is the size of the initialization vector.
	TunnelIVSize = 16
	// TunnelPayloadOffset is the byte offset of the encrypted payload region.
	TunnelPayloadOffset = TunnelIVOffset + TunnelIVSize // 20
	// TunnelPayloadSize is the size of the encrypted payload region.
	TunnelPayloadSize = 1008
)

// Error definitions for tunnel cryptographic operations using structured error handling.
// These errors follow the oops pattern for consistent error wrapping and context preservation.
var (
	// ErrInvalidKeySize indicates that a provided key does not meet the required size.
	// AES-256 requires exactly 32-byte keys for both layer and IV encryption.
	ErrInvalidKeySize = oops.Errorf("invalid key size: must be 32 bytes for AES-256")

	// ErrInvalidKey indicates that a provided key is cryptographically invalid.
	// This occurs when a key is all zeros or contains invalid/weak values.
	ErrInvalidKey = oops.Errorf("invalid key: key cannot be all zeros or weak")

	// ErrCipherCreationFailed indicates that AES cipher initialization failed.
	// This typically occurs due to invalid key material or system-level cryptographic failures.
	ErrCipherCreationFailed = oops.Errorf("failed to create AES cipher block")

	// ErrNilTunnelData indicates that a nil TunnelData pointer was passed to encryption/decryption.
	// It is reserved and is not currently returned by this package: the exported
	// Encrypt/Decrypt entry points take byte slices and copy them into a
	// value-type TunnelData, so no code path can observe a nil pointer.
	ErrNilTunnelData = oops.Errorf("tunnel data cannot be nil")

	// ErrEncryptionFailed indicates that the encryption operation failed.
	// This may occur due to invalid data, corrupted keys, or cryptographic processing errors.
	ErrEncryptionFailed = oops.Errorf("tunnel encryption failed")

	// ErrDecryptionFailed indicates that the decryption operation failed.
	// This may occur due to invalid ciphertext, incorrect keys, or authentication failures.
	ErrDecryptionFailed = oops.Errorf("tunnel decryption failed")

	// ErrUnsupportedEncryptionType indicates an unsupported tunnel encryption scheme was requested.
	// TunnelEncryptionAES (0) is the only layer encryption type defined by the I2P
	// specifications, so it is the only accepted value; anything else, including
	// the deprecated TunnelEncryptionECIES tombstone, returns this error.
	ErrUnsupportedEncryptionType = oops.Errorf("unsupported tunnel encryption type")
)
