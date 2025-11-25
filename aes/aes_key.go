package aes

import (
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// AESSymmetricKey represents a symmetric key for AES encryption/decryption.
//
// CRITICAL: Never create AESSymmetricKey using zero-value construction or direct struct literals.
// Zero-value construction results in nil slices which:
//   - Will panic when calling NewEncrypter() or NewDecrypter()
//   - Violates AES security requirements
//   - Cannot be detected until runtime
//
// ALWAYS use NewAESKey() or variant constructors for safe construction.
//
// WRONG - Will panic:
//
//	var key AESSymmetricKey              // nil slices - will panic!
//	key := AESSymmetricKey{...}          // no validation
//
// CORRECT - Use constructor:
//
//	key, err := aes.NewAESKey(keyBytes, ivBytes)
//	if err != nil {
//	    return err
//	}
//	defer key.Zero()  // Always zero sensitive key material
type AESSymmetricKey struct {
	Key []byte // AES key (must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256)
	IV  []byte // Initialization Vector (must be 16 bytes for AES)
}

// NewAESKey creates a validated AES symmetric key with IV.
//
// This constructor provides mandatory validation to prevent common security issues:
//   - Rejects keys that are not 16, 24, or 32 bytes (AES-128/192/256)
//   - Rejects IVs that are not exactly 16 bytes
//   - Returns defensive copies to prevent external mutation
//
// Parameters:
//   - key: Must be 16, 24, or 32 bytes for AES-128/192/256
//   - iv: Must be exactly 16 bytes
//
// Returns an error if:
//   - Key size is invalid
//   - IV size is invalid
//
// Example usage:
//
//	key, err := aes.NewAESKey(keyBytes, ivBytes)
//	if err != nil {
//	    return err
//	}
//	defer key.Zero()
func NewAESKey(key, iv []byte) (*AESSymmetricKey, error) {
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, oops.Errorf("invalid AES key size: expected 16, 24, or 32 bytes, got %d bytes", keyLen)
	}
	if len(iv) != 16 {
		return nil, oops.Errorf("invalid AES IV size: expected 16 bytes, got %d bytes", len(iv))
	}

	// Create defensive copies to prevent external mutation
	keyCopy := make([]byte, keyLen)
	ivCopy := make([]byte, 16)
	copy(keyCopy, key)
	copy(ivCopy, iv)

	return &AESSymmetricKey{
		Key: keyCopy,
		IV:  ivCopy,
	}, nil
}

// NewAES256Key is a convenience constructor for AES-256 keys.
// AES-256 provides the strongest security level and is recommended for most use cases.
//
// Parameters:
//   - key: Must be exactly 32 bytes
//   - iv: Must be exactly 16 bytes
//
// Returns an error if sizes are invalid.
//
// Example usage:
//
//	key, err := aes.NewAES256Key(keyBytes, ivBytes)
//	if err != nil {
//	    return err
//	}
//	defer key.Zero()
func NewAES256Key(key, iv []byte) (*AESSymmetricKey, error) {
	if len(key) != 32 {
		return nil, oops.Errorf("AES-256 requires exactly 32-byte key, got %d bytes", len(key))
	}
	return NewAESKey(key, iv)
}

// NewAES192Key is a convenience constructor for AES-192 keys.
//
// Parameters:
//   - key: Must be exactly 24 bytes
//   - iv: Must be exactly 16 bytes
//
// Returns an error if sizes are invalid.
func NewAES192Key(key, iv []byte) (*AESSymmetricKey, error) {
	if len(key) != 24 {
		return nil, oops.Errorf("AES-192 requires exactly 24-byte key, got %d bytes", len(key))
	}
	return NewAESKey(key, iv)
}

// NewAES128Key is a convenience constructor for AES-128 keys.
//
// Parameters:
//   - key: Must be exactly 16 bytes
//   - iv: Must be exactly 16 bytes
//
// Returns an error if sizes are invalid.
func NewAES128Key(key, iv []byte) (*AESSymmetricKey, error) {
	if len(key) != 16 {
		return nil, oops.Errorf("AES-128 requires exactly 16-byte key, got %d bytes", len(key))
	}
	return NewAESKey(key, iv)
}

// NewEncrypter creates a new AESSymmetricEncrypter
func (k *AESSymmetricKey) NewEncrypter() (types.Encrypter, error) {
	log.Debug("Creating new AESSymmetricEncrypter")

	// Validate key size (must be 16, 24, or 32 bytes for AES)
	keyLen := len(k.Key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		log.WithField("key_length", keyLen).Error("Invalid AES key size")
		return nil, ErrInvalidKeySize
	}

	// Validate IV size (must be 16 bytes for AES)
	if len(k.IV) != 16 {
		log.WithField("iv_length", len(k.IV)).Error("Invalid AES IV size")
		return nil, ErrInvalidIVSize
	}

	return &AESSymmetricEncrypter{
		Key: k.Key,
		IV:  k.IV,
	}, nil
}

// Len returns the length of the key
func (k *AESSymmetricKey) Len() int {
	return len(k.Key)
}

// NewDecrypter creates a new AESSymmetricDecrypter
func (k *AESSymmetricKey) NewDecrypter() (types.Decrypter, error) {
	log.Debug("Creating new AESSymmetricDecrypter")

	// Validate key size (must be 16, 24, or 32 bytes for AES)
	keyLen := len(k.Key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		log.WithField("key_length", keyLen).Error("Invalid AES key size")
		return nil, ErrInvalidKeySize
	}

	// Validate IV size (must be 16 bytes for AES)
	if len(k.IV) != 16 {
		log.WithField("iv_length", len(k.IV)).Error("Invalid AES IV size")
		return nil, ErrInvalidIVSize
	}

	return &AESSymmetricDecrypter{
		Key: k.Key,
		IV:  k.IV,
	}, nil
}

// Zero implements secure memory cleanup for sensitive key material.
// Clears both the AES key and IV from memory.
func (k *AESSymmetricKey) Zero() {
	log.Debug("Securely clearing AES key material from memory")

	// Overwrite key with zeros
	for i := range k.Key {
		k.Key[i] = 0
	}

	// Overwrite IV with zeros
	for i := range k.IV {
		k.IV[i] = 0
	}

	log.Debug("AES key material securely erased")
}
