package tunnel

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// TunnelEncryptor defines the interface for tunnel-level encryption operations.
// The abstraction has two implementations: AES-256-CBC, the only scheme the I2P
// specifications define for tunnel *layer* encryption, and ECIES-X25519, an
// experimental wrapper around the end-to-end ecies package that is not a tunnel
// scheme at all (see [TunnelEncryptionECIES]).
//
// Note that tunnel *building* is a separate concern from tunnel layer
// encryption and is ECIES-based in current I2P; that crypto lives in this
// package's build-record functions ([EncryptBuildRequest] and friends), not in
// this interface.
// Implementations must provide secure encryption/decryption with proper error handling.
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

// TunnelEncryptionType distinguishes between tunnel *layer* encryption schemes -
// the symmetric encryption of each 1028-byte tunnel message, which is a
// different concern from tunnel *building* (which is ECIES-based; see
// [EncryptBuildRequest]). I2P's specifications define only AES (type 0) for
// layer encryption. Use [TunnelEncryptionAES] for anything that has to talk to a
// real router; [TunnelEncryptionECIES] is experimental and not interoperable.
type TunnelEncryptionType uint8

const (
	// TunnelEncryptionAES is the AES-256-CBC tunnel layer encryption scheme,
	// and the only layer encryption type defined by the I2P specifications
	// (Tunnel-Creation-ECIES: "The only layer encryption currently supported is
	// type 0, which is AES"). Use this for anything that must interoperate.
	// It uses dual-layer AES encryption with separate layer and IV keys.
	// Tunnel records are 1028 bytes: a 16-byte IV prefix followed by the
	// encrypted payload region (bytes 16..1024 are CBC-processed; the final 4
	// bytes are carried through unchanged).
	TunnelEncryptionAES TunnelEncryptionType = 0

	// TunnelEncryptionECIES is EXPERIMENTAL and NOT interoperable as a tunnel
	// LAYER encryption scheme. No I2P specification defines an ECIES/ChaCha20
	// tunnel layer encryption type: Tunnel-Creation-ECIES lists type 1 only as
	// "for future (ChaCha?)" and says adding such types "is a topic for
	// additional research, and is not currently a part of this specification".
	// (ECIES-X25519 IS the deployed standard for tunnel BUILDING - see
	// [EncryptBuildRequest] - but that is a different layer, and this value
	// implements neither of those formats.) The ECIES-X25519-AEAD-Ratchet spec
	// this is often assumed to implement is end-to-end (destination to
	// destination) and does not define tunnel layer encryption at all.
	//
	// This value wraps the ecies package's one-time format, so records are
	// variable length: 96 bytes of overhead plus the plaintext (Elligator2-
	// encoded ephemeral key + flags section + payload + tag). Measured: a
	// 1-byte payload yields 97 bytes, a 222-byte payload 318 bytes, and a
	// full 1008-byte tunnel payload 1104 bytes - larger than the fixed
	// 1028-byte AES record. Variable-length records also defeat the fixed-size
	// tunnel layout that stops intermediate hops from observing payload sizes.
	//
	// The local value 1 is this package's own choice; it is not the spec's
	// layer encryption type 1, and it is distinct from the LS2 crypto type 4
	// used in LeaseSet2 records. Do not advertise it to a router.
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
// For AES encryption (type 0), the only scheme defined by the I2P specifications:
//   - layerKey: 32-byte AES-256 key for data layer encryption
//   - ivKey: 32-byte AES-256 key for IV encryption
//
// For ECIES encryption (type 1), which is experimental and not interoperable:
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
