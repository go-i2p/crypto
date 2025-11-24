// Package kdf provides consistent key derivation functions for the I2P cryptographic ecosystem.
//
// This package standardizes key derivation across all I2P components, ensuring that
// keys are derived consistently and securely using HKDF (HMAC-based Key Derivation Function)
// as defined in RFC 5869.
//
// # Key Features
//
//   - Unified API for deriving keys from root secrets
//   - Standard info strings for different I2P purposes
//   - Type-safe key purpose enumeration
//   - Multiple key derivation support
//
// # Usage Example
//
//	// Derive keys from an ECIES shared secret
//	kd := kdf.NewKeyDerivation(eciesSharedSecret)
//
//	// Derive specific purpose keys
//	tunnelKey, _ := kd.DeriveForPurpose(kdf.PurposeTunnelEncryption)
//	garlicKey, _ := kd.DeriveForPurpose(kdf.PurposeGarlicEncryption)
//
//	// Derive multiple related keys
//	keys, _ := kd.DeriveKeys([]byte("custom-context"), 3)
//
// # Standard Key Purposes
//
// The package defines standard key purposes for I2P protocol components:
//   - PurposeTunnelEncryption - Keys for tunnel layer encryption
//   - PurposeGarlicEncryption - Keys for garlic message encryption
//   - PurposeSessionTag - Keys for session tag generation
//   - PurposeRatchetChain - Keys for ratchet chain initialization
//   - PurposeIVGeneration - Keys for IV/nonce generation
//
// # Security Considerations
//
//   - Root keys should be generated using cryptographically secure random sources
//   - Use standard key purposes when possible for consistency
//   - Custom info strings should include context-specific prefixes
//   - Derived keys should be unique per purpose and context
package kdf

import (
	"github.com/go-i2p/crypto/hkdf"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// KeyPurpose identifies what a derived key will be used for.
// This ensures keys are derived with purpose-specific context strings.
type KeyPurpose int

const (
	// PurposeTunnelEncryption is for deriving tunnel layer encryption keys
	PurposeTunnelEncryption KeyPurpose = iota

	// PurposeGarlicEncryption is for deriving garlic message encryption keys
	PurposeGarlicEncryption

	// PurposeSessionTag is for deriving session tag generation keys
	PurposeSessionTag

	// PurposeRatchetChain is for deriving ratchet chain keys
	PurposeRatchetChain

	// PurposeIVGeneration is for deriving IV/nonce generation keys
	PurposeIVGeneration

	// PurposeMessageKey is for deriving per-message encryption keys
	PurposeMessageKey

	// PurposeHandshake is for deriving handshake-related keys
	PurposeHandshake

	// PurposeEncryptedLeaseSetEncryption is used when deriving symmetric
	// encryption keys for EncryptedLeaseSet inner data.
	//
	// The encryption key is derived from:
	//   - ECDH shared secret (X25519)
	//   - EncryptedLeaseSet cookie (32 bytes)
	//   - This purpose constant
	//
	// Info string: "i2p-encrypted-leaseset-encryption"
	//
	// Spec: I2P Proposal 123 - Encrypted LeaseSet
	PurposeEncryptedLeaseSetEncryption
)

// Standard info strings for each key purpose
var purposeInfo = map[KeyPurpose]string{
	PurposeTunnelEncryption:            "I2P-Tunnel-Encryption-v1",
	PurposeGarlicEncryption:            "I2P-Garlic-Encryption-v1",
	PurposeSessionTag:                  "I2P-Session-Tag-v1",
	PurposeRatchetChain:                "I2P-Ratchet-Chain-v1",
	PurposeIVGeneration:                "I2P-IV-Generation-v1",
	PurposeMessageKey:                  "I2P-Message-Key-v1",
	PurposeHandshake:                   "I2P-Handshake-v1",
	PurposeEncryptedLeaseSetEncryption: "i2p-encrypted-leaseset-encryption",
}

// Package-level logger
var log = logger.GetGoI2PLogger()

// KeyDerivation provides consistent key derivation from a root key.
// All derived keys use HKDF-SHA256 with purpose-specific info strings.
type KeyDerivation struct {
	rootKey [32]byte
}

// NewKeyDerivation creates a new key derivation context from a root key.
// The root key should be a high-entropy secret such as:
//   - ECIES shared secret
//   - Master session key
//   - DH shared secret
//
// Parameters:
//   - rootKey: A 32-byte root key
//
// Returns:
//   - *KeyDerivation: The key derivation context
//
// Example:
//
//	// From ECIES shared secret
//	kd := kdf.NewKeyDerivation(eciesSharedSecret)
//
//	// From DH key agreement
//	sharedSecret, _ := dhPrivate.SharedKey(dhPublic)
//	kd := kdf.NewKeyDerivation([32]byte(sharedSecret))
func NewKeyDerivation(rootKey [32]byte) *KeyDerivation {
	return &KeyDerivation{
		rootKey: rootKey,
	}
}

// DeriveForPurpose derives a single 32-byte key for a specific I2P purpose.
// This uses standard info strings defined for each purpose.
//
// Parameters:
//   - purpose: The intended use of the derived key
//
// Returns:
//   - [32]byte: The derived key
//   - error: Any error during derivation
//
// Example:
//
//	kd := kdf.NewKeyDerivation(rootKey)
//
//	// Derive keys for different purposes
//	tunnelKey, _ := kd.DeriveForPurpose(kdf.PurposeTunnelEncryption)
//	garlicKey, _ := kd.DeriveForPurpose(kdf.PurposeGarlicEncryption)
//	tagKey, _ := kd.DeriveForPurpose(kdf.PurposeSessionTag)
func (kd *KeyDerivation) DeriveForPurpose(purpose KeyPurpose) ([32]byte, error) {
	info, ok := purposeInfo[purpose]
	if !ok {
		return [32]byte{}, oops.Errorf("unknown key purpose: %d", purpose)
	}

	log.WithField("purpose", info).Debug("Deriving key for purpose")

	return kd.DeriveWithInfo(info)
}

// DeriveWithInfo derives a single 32-byte key using a custom info string.
// Use this when you need non-standard key derivation contexts.
//
// Parameters:
//   - info: Context-specific info string (should be unique per use case)
//
// Returns:
//   - [32]byte: The derived key
//   - error: Any error during derivation
//
// Example:
//
//	// Derive key for custom protocol extension
//	customKey, _ := kd.DeriveWithInfo("MyApp-Extension-v1")
//
//	// Derive key with session-specific context
//	sessionKey, _ := kd.DeriveWithInfo(fmt.Sprintf("Session-%s", sessionID))
func (kd *KeyDerivation) DeriveWithInfo(info string) ([32]byte, error) {
	log.WithField("info", info).Debug("Deriving key with custom info")

	hkdfDeriver := hkdf.NewHKDF()
	derived, err := hkdfDeriver.Derive(kd.rootKey[:], nil, []byte(info), 32)
	if err != nil {
		return [32]byte{}, oops.Wrapf(err, "HKDF derivation failed")
	}

	var key [32]byte
	copy(key[:], derived)

	return key, nil
}

// DeriveKeys derives multiple 32-byte keys from the same context.
// This is useful when you need several related keys (e.g., encrypt + MAC + IV).
//
// Parameters:
//   - info: Context-specific info string
//   - count: Number of keys to derive
//
// Returns:
//   - [][32]byte: Slice of derived keys
//   - error: Any error during derivation
//
// Example:
//
//	// Derive 3 keys for encryption, MAC, and IV generation
//	keys, _ := kd.DeriveKeys([]byte("Tunnel-Layer-42"), 3)
//	encryptKey := keys[0]
//	macKey := keys[1]
//	ivKey := keys[2]
func (kd *KeyDerivation) DeriveKeys(info []byte, count int) ([][32]byte, error) {
	if count <= 0 {
		return nil, oops.Errorf("key count must be positive")
	}

	log.WithField("info", string(info)).
		WithField("count", count).
		Debug("Deriving multiple keys")

	// Derive count * 32 bytes
	outputLen := count * 32

	hkdfDeriver := hkdf.NewHKDF()
	derived, err := hkdfDeriver.Derive(kd.rootKey[:], nil, info, outputLen)
	if err != nil {
		return nil, oops.Wrapf(err, "HKDF multi-key derivation failed")
	}

	// Split into individual keys
	keys := make([][32]byte, count)
	for i := 0; i < count; i++ {
		copy(keys[i][:], derived[i*32:(i+1)*32])
	}

	log.WithField("keys_derived", count).Debug("Multi-key derivation successful")

	return keys, nil
}

// DeriveSessionKeys is a convenience function that derives the standard set of keys
// needed for an I2P session: ratchet root key, symmetric chain key, and tag chain key.
//
// This is equivalent to DeriveKeys() but with semantic naming for session initialization.
//
// Returns:
//   - rootKey: Key for DH ratchet initialization
//   - symKey: Key for symmetric ratchet chain
//   - tagKey: Key for session tag ratchet
//   - error: Any error during derivation
//
// Example:
//
//	kd := kdf.NewKeyDerivation(eciesSharedSecret)
//	rootKey, symKey, tagKey, err := kd.DeriveSessionKeys()
//	if err != nil {
//	    return err
//	}
//
//	// Initialize session ratchets
//	dhRatchet := ratchet.NewDHRatchet(rootKey, ourPriv, theirPub)
//	symRatchet := ratchet.NewSymmetricRatchet(symKey)
//	tagRatchet := ratchet.NewTagRatchet(tagKey)
func (kd *KeyDerivation) DeriveSessionKeys() (rootKey, symKey, tagKey [32]byte, err error) {
	log.Debug("Deriving standard session keys")

	keys, err := kd.DeriveKeys([]byte("ECIES-Session-KDF"), 3)
	if err != nil {
		return rootKey, symKey, tagKey, err
	}

	rootKey = keys[0]
	symKey = keys[1]
	tagKey = keys[2]

	log.Debug("Session keys derived successfully")

	return rootKey, symKey, tagKey, nil
}

// Zero securely clears the root key from memory.
// Call this when the KeyDerivation instance is no longer needed.
func (kd *KeyDerivation) Zero() {
	for i := range kd.rootKey {
		kd.rootKey[i] = 0
	}
	log.Debug("KeyDerivation state cleared")
}
