package tunnel

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// TunnelEncryptor defines the interface for tunnel-level encryption operations.
// This abstraction supports multiple encryption schemes (AES-256-CBC and ECIES-X25519)
// allowing I2P routers to handle both legacy and modern tunnel encryption formats.
// Implementations must provide secure encryption/decryption with proper error handling
// and follow I2P protocol specifications for network compatibility.
type TunnelEncryptor interface {
	// Encrypt encrypts plaintext data and returns the ciphertext.
	// For AES: accepts 1008 bytes of payload (a random 16-byte IV is prepended)
	// or a full 1028-byte record, and returns a 1028-byte record. Note that only
	// bytes 16..1024 of the record are CBC-processed; the final 4 bytes are left
	// as provided.
	// For ECIES: accepts variable-length data up to the ECIES max plaintext size
	// and returns the ECIES one-time format (96 bytes of overhead plus the
	// payload).
	// Returns error if encryption fails due to invalid keys or cryptographic operations.
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext data and returns the plaintext.
	// For AES: expects 1028 bytes of tunnel data and returns the 1008-byte
	// payload from bytes 16..1024 (excluding the 16-byte IV prefix).
	// For ECIES: expects ECIES-formatted ciphertext, returns original plaintext
	// Returns error if decryption fails due to invalid keys, corrupted data, or authentication failures.
	Decrypt(ciphertext []byte) ([]byte, error)

	// Type returns the encryption scheme used by this encryptor.
	// This enables routers to identify and handle different tunnel encryption formats.
	Type() TunnelEncryptionType
}

// TunnelEncryptionType distinguishes between different tunnel encryption schemes.
// I2P supports multiple encryption types for backward compatibility and gradual migration.
// New tunnels should use ECIES-X25519 (type 1) by default, with AES-256-CBC (type 0)
// available for legacy router interoperability during the transition period.
type TunnelEncryptionType uint8

const (
	// TunnelEncryptionAES represents the legacy AES-256-CBC encryption scheme.
	// This uses dual-layer AES encryption with separate layer and IV keys.
	// Tunnel records are 1028 bytes: a 16-byte IV prefix followed by the
	// encrypted payload region (bytes 16..1024 are CBC-processed; the final 4
	// bytes are carried through unchanged).
	TunnelEncryptionAES TunnelEncryptionType = 0

	// TunnelEncryptionECIES represents the modern ECIES-X25519 encryption scheme.
	// This uses X25519 key agreement with ChaCha20-Poly1305 AEAD encryption.
	// Records are variable length: 96 bytes of overhead plus the plaintext
	// (Elligator2-encoded ephemeral key + flags section + payload + tags). For
	// small payloads this is far below the fixed 1028-byte AES record, but for a
	// full 1008-byte tunnel payload the ECIES record (1104 bytes) is larger than
	// AES, so the savings depend on payload size.
	// See [I2P Spec: ECIES-X25519-AEAD](https://i2p.net/en/docs/specs/ecies/)
	// for the wire format. Note: this local type (1) is distinct from the LS2
	// crypto type (4) used in LeaseSet2 records.
	TunnelEncryptionECIES TunnelEncryptionType = 1
)

// String returns the human-readable name of the encryption type for logging and debugging.
func (t TunnelEncryptionType) String() string {
	switch t {
	case TunnelEncryptionAES:
		return "AES-256-CBC"
	case TunnelEncryptionECIES:
		return "ECIES-X25519"
	default:
		return "Unknown"
	}
}

// NewTunnelEncryptor creates a new tunnel encryptor based on the specified encryption type.
// This factory function provides a unified interface for creating both AES and ECIES encryptors.
//
// For AES encryption (type 0):
//   - layerKey: 32-byte AES-256 key for data layer encryption
//   - ivKey: 32-byte AES-256 key for IV encryption
//
// For ECIES encryption (type 1):
//   - recipientPubKey: 32-byte X25519 public key (layerKey parameter)
//   - ivKey parameter is ignored for ECIES
//
// Returns configured TunnelEncryptor or error if creation fails due to invalid parameters.
func NewTunnelEncryptor(encType TunnelEncryptionType, layerKey, ivKey TunnelKey) (TunnelEncryptor, error) {
	log.WithFields(logger.Fields{"pkg": "tunnel", "func": "NewTunnelEncryptor", "encryption_type": encType.String()}).Debug("Creating tunnel encryptor")

	switch encType {
	case TunnelEncryptionAES:
		// Create legacy AES-256-CBC encryptor for backward compatibility
		aes, err := NewAESEncryptor(layerKey, ivKey)
		if err != nil {
			return nil, oops.Wrapf(err, "failed to create AES encryptor")
		}
		return aes, nil

	case TunnelEncryptionECIES:
		// Create ECIES-X25519 encryptor using layerKey as recipient public key
		var recipientPubKey [32]byte
		copy(recipientPubKey[:], layerKey[:])
		ecies := NewECIESEncryptor(recipientPubKey)
		return ecies, nil

	default:
		return nil, ErrUnsupportedEncryptionType
	}
}
