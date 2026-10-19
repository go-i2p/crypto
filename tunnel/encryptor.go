package tunnel

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// TunnelEncryptor defines the interface for tunnel-level encryption operations.
//
// AES-256-CBC ([AESEncryptor]) is the only implementation, because it is the
// only scheme the I2P specifications define for tunnel *layer* encryption
// (Tunnel-Creation-ECIES, "Layer Encryption": "The only layer encryption
// currently supported is type 0, which is AES").
//
// Note that tunnel *building* is a separate concern from tunnel layer
// encryption and is ECIES-based in current I2P; that crypto lives in this
// package's build-record functions ([EncryptBuildRequest] and friends), not in
// this interface.
// Implementations must provide secure encryption/decryption with proper error handling.
type TunnelEncryptor interface {
	// Encrypt encrypts plaintext data and returns the ciphertext.
	// For AES: accepts 1008 bytes of payload (a random 16-byte IV is written at
	// bytes 4..19) or a full 1028-byte record, and returns a 1028-byte record.
	// Per the Tunnel Message specification, bytes 20..1027 are the CBC-processed
	// payload region; bytes 0..3 (the cleartext tunnel ID) are carried through
	// untouched.
	// Returns error if encryption fails due to invalid keys or cryptographic operations.
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext data and returns the plaintext.
	// For AES: expects 1028 bytes of tunnel data and returns the 1008-byte
	// payload from bytes 20..1027 (excluding the 4-byte tunnel ID and the
	// 16-byte IV).
	// Returns error if decryption fails due to invalid keys, corrupted data, or authentication failures.
	Decrypt(ciphertext []byte) ([]byte, error)

	// Type returns the encryption scheme used by this encryptor.
	// This enables routers to identify and handle different tunnel encryption formats.
	Type() TunnelEncryptionType
}

// TunnelEncryptionType distinguishes between tunnel *layer* encryption schemes -
// the symmetric encryption of each 1028-byte tunnel message, which is a
// different concern from tunnel *building* (which is ECIES-based; see
// [EncryptBuildRequest]). I2P's specifications define only AES (type 0) for
// layer encryption, so [TunnelEncryptionAES] is the only usable value.
type TunnelEncryptionType uint8

const (
	// TunnelEncryptionAES is the AES-256-CBC tunnel layer encryption scheme,
	// and the only layer encryption type defined by the I2P specifications
	// (Tunnel-Creation-ECIES: "The only layer encryption currently supported is
	// type 0, which is AES"). Use this for anything that must interoperate.
	// It uses dual-layer AES encryption with separate layer and IV keys.
	// Tunnel records are 1028 bytes: a 4-byte cleartext tunnel ID, a 16-byte IV
	// at bytes 4..19, and the encrypted payload region at bytes 20..1027.
	TunnelEncryptionAES TunnelEncryptionType = 0

	// TunnelEncryptionECIES is a deprecated tombstone, NOT a usable tunnel
	// layer encryption scheme. No I2P specification defines an ECIES/ChaCha20
	// tunnel layer encryption type: Tunnel-Creation-ECIES, "Layer Encryption",
	// states "The only layer encryption currently supported is type 0, which is
	// AES" and "Adding new layer encryption types, for example ChaCha20, is a
	// topic for additional research, and is not currently a part of this
	// specification". The build-request record's layer-encryption-type field
	// lists "0 for AES (as in current tunnels); 1 for future (ChaCha?)", so
	// type 1 is reserved-but-undefined and implemented by no router.
	//
	// This package previously exposed ECIESEncryptor/ECIESDecryptor wrapping
	// the ecies package's *end-to-end* one-time format under this value. That
	// was never a tunnel scheme: it is destination-to-destination, and it
	// produces variable-length records (a full 1008-byte tunnel payload came
	// out at 1104 bytes), which defeats the fixed-size tunnel layout whose
	// purpose is to stop intermediate hops from observing payload sizes. Those
	// types have been removed; NewTunnelEncryptor now rejects this value.
	//
	// The numeric value 1 is retained only so that code which already stores
	// it keeps compiling and fails loudly at construction time rather than
	// silently. It is distinct from the LS2 crypto type 4 used for
	// ECIES-X25519 in LeaseSet2 records. Never advertise it to a router.
	//
	// Deprecated: there is no interoperable implementation. Use
	// TunnelEncryptionAES. ECIES-X25519 IS the deployed standard for tunnel
	// *building* (see EncryptBuildRequest), which is a different layer.
	TunnelEncryptionECIES TunnelEncryptionType = 1
)

// String returns the human-readable name of the encryption type for logging and debugging.
func (t TunnelEncryptionType) String() string {
	switch t {
	case TunnelEncryptionAES:
		return "AES-256-CBC"
	case TunnelEncryptionECIES:
		return "ECIES-X25519 (not a tunnel scheme; deprecated)"
	default:
		return "Unknown"
	}
}

// NewTunnelEncryptor creates a new tunnel encryptor based on the specified encryption type.
// AES (type 0) is the only layer encryption scheme defined by the I2P
// specifications, so it is the only accepted value.
//
//   - layerKey: 32-byte AES-256 key for data layer encryption
//   - ivKey: 32-byte AES-256 key for IV encryption
//
// Returns a configured TunnelEncryptor, or an error for any type other than
// [TunnelEncryptionAES] - including the deprecated [TunnelEncryptionECIES]
// tombstone, which has no interoperable implementation.
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
		// Rejected: no I2P specification defines an ECIES tunnel layer
		// encryption type. See the TunnelEncryptionECIES doc comment.
		return nil, oops.Wrapf(ErrUnsupportedEncryptionType,
			"tunnel layer encryption type %d is not defined by any I2P specification; only %d (AES-256-CBC) interoperates",
			TunnelEncryptionECIES, TunnelEncryptionAES)

	default:
		return nil, ErrUnsupportedEncryptionType
	}
}
