// Package kdf derives the many different keys that I2P needs from a single
// shared secret.
//
// # What this package does
//
// In I2P, two routers first agree on one shared secret (for example, through
// an X25519 key exchange). From that single secret, the protocol needs many
// different keys: one for tunnel encryption, one for message encryption, one
// for session tags, and so on. This package derives all of those keys in a
// consistent way.
//
// It uses HKDF (HMAC-based Key Derivation Function), a standard method
// defined in RFC 5869, with SHA-256 as the hash. Each key is derived with a
// purpose-specific "info" string so that keys for different jobs never
// collide.
//
// # Usage
//
//	// Start from a shared secret.
//	kd := kdf.NewKeyDerivation(sharedSecret)
//
//	// Derive a key for a specific purpose.
//	tunnelKey, _ := kd.DeriveForPurpose(kdf.PurposeTunnelEncryption)
//
// # Key purposes
//
// The KeyPurpose type names the standard jobs a derived key can be used for,
// such as tunnel encryption, garlic message encryption, session tags, and
// ratchet chains. Using the standard purposes keeps keys consistent across
// the whole I2P ecosystem.
//
// # Security considerations
//
//   - Generate root secrets from a cryptographically secure random source.
//   - Prefer the standard key purposes so keys stay consistent.
//   - Keep each derived key unique to its purpose and context.
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

	// PurposeAttachPayload is for deriving keys for attached payload encryption
	// in New Session (NS) and New Session Reply (NSR) messages.
	// Java I2P compatible - uses "AttachPayloadKDF" info string.
	PurposeAttachPayload

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

// purposeInfo maps each key purpose to the "info" string used by HKDF.
// These strings are the context that keeps keys for different jobs distinct.
var purposeInfo = map[KeyPurpose]string{
	PurposeTunnelEncryption:            "I2P-Tunnel-Encryption-v1",
	PurposeGarlicEncryption:            "I2P-Garlic-Encryption-v1",
	PurposeSessionTag:                  "SessionReplyTags",
	PurposeRatchetChain:                "I2P-Ratchet-Chain-v1",
	PurposeIVGeneration:                "I2P-IV-Generation-v1",
	PurposeMessageKey:                  "I2P-Message-Key-v1",
	PurposeHandshake:                   "I2P-Handshake-v1",
	PurposeAttachPayload:               "AttachPayloadKDF",
	PurposeEncryptedLeaseSetEncryption: "i2p-encrypted-leaseset-encryption",
}

// Package-level logger
var log = logger.GetGoI2PLogger()

// KeyDerivation provides consistent key derivation from a root key.
// All derived keys use HKDF-SHA256 with purpose-specific info strings.
//
// # Protocol scope
//
// KeyDerivation is the KDF for the legacy ECIES-X25519-AEAD-Ratchet protocol
// (see crypto/ecies and crypto/ratchet.Session). It is NOT the KDF used by the
// spec-compliant I2P Noise path (Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256),
// which is implemented in go-noise/ratchet and uses StandardHKDF directly with
// the spec-mandated salt/ikm/info arguments.
//
// The two protocols are distinct and self-consistent; do not mix them. For the
// spec-compliant Noise data-phase KDFs, use StandardHKDF with the exact
// (salt, ikm, info) values from the I2P spec rather than these methods.
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

	log.WithFields(logger.Fields{"pkg": "kdf", "func": "KeyDerivation.DeriveForPurpose", "purpose": info}).Debug("Deriving key for purpose")

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
	log.WithFields(logger.Fields{"pkg": "kdf", "func": "KeyDerivation.DeriveWithInfo", "info": info}).Debug("Deriving key with custom info")

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

	log.WithFields(logger.Fields{"pkg": "kdf", "func": "KeyDerivation.DeriveKeys", "info": string(info), "count": count}).Debug("Deriving multiple keys")

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

	log.WithFields(logger.Fields{"pkg": "kdf", "func": "KeyDerivation.DeriveKeys", "keys_derived": count}).Debug("Multi-key derivation successful")

	return keys, nil
}

// DeriveSessionKeys is a convenience function that derives the standard set of keys
// needed for an I2P session: ratchet root key, symmetric chain key, and tag chain key.
//
// This is equivalent to DeriveKeys() but with semantic naming for session initialization.
//
// NOTE: This uses the legacy ECIES-X25519-AEAD-Ratchet protocol's KDF with the
// "ECIES-Session-KDF" info string. It is NOT the spec-compliant I2P Noise
// data-phase KDF (which uses HKDF with the spec's exact salt/ikm/info values).
// Do not use this for the Noise_IKelg2+hs2 path; use StandardHKDF there instead.
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
	log.WithFields(logger.Fields{"pkg": "kdf", "func": "KeyDerivation.DeriveSessionKeys"}).Debug("Deriving standard session keys")

	keys, err := kd.DeriveKeys([]byte("ECIES-Session-KDF"), 3)
	if err != nil {
		return rootKey, symKey, tagKey, err
	}

	rootKey = keys[0]
	symKey = keys[1]
	tagKey = keys[2]

	log.WithFields(logger.Fields{"pkg": "kdf", "func": "KeyDerivation.DeriveSessionKeys"}).Debug("Session keys derived successfully")

	return rootKey, symKey, tagKey, nil
}

// Zero securely clears the root key from memory.
// Call this when the KeyDerivation instance is no longer needed.
func (kd *KeyDerivation) Zero() {
	for i := range kd.rootKey {
		kd.rootKey[i] = 0
	}
	log.WithFields(logger.Fields{"pkg": "kdf", "func": "KeyDerivation.Zero"}).Debug("KeyDerivation state cleared")
}

// StandardHKDF performs a one-shot RFC 5869 HKDF-SHA256 key derivation.
// This is a convenience function for callers that need a single HKDF invocation
// without constructing a KeyDerivation context. It is the canonical implementation
// of raw HKDF extract-and-expand in the crypto layer, replacing ad-hoc inline
// implementations found in higher-level packages (e.g., noise handshakes, NTCP2).
//
// Parameters:
//   - salt: Optional salt value (can be nil; HKDF will use a zero-filled salt)
//   - ikm: Input key material (must not be empty)
//   - info: Optional context/application-specific info (can be nil)
//   - length: Desired output length in bytes (must be > 0; max 255*32 per RFC 5869)
//
// Returns:
//   - []byte: Derived key material of the requested length
//   - error: Any error during derivation
//
// Example usage:
//
//	derived, err := kdf.StandardHKDF(salt, sharedSecret, []byte("NTCP2-KDF"), 32)
//	if err != nil {
//	    return err
//	}
func StandardHKDF(salt, ikm, info []byte, length int) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "kdf", "func": "StandardHKDF", "ikm_length": len(ikm), "salt_length": len(salt), "info_length": len(info), "output_length": length}).Debug("StandardHKDF derivation")

	deriver := hkdf.NewHKDF()
	derived, err := deriver.Derive(ikm, salt, info, length)
	if err != nil {
		return nil, oops.Wrapf(err, "StandardHKDF derivation failed")
	}

	log.WithFields(logger.Fields{"pkg": "kdf", "func": "StandardHKDF", "derived_length": len(derived)}).Debug("StandardHKDF derivation successful")
	return derived, nil
}
