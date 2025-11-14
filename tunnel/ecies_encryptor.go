// Package tunnel provides I2P tunnel encryption implementations.
// This file implements ECIES-X25519 tunnel encryption as a wrapper around the ecies package.
package tunnel

import (
	"github.com/go-i2p/crypto/ecies"
	"github.com/samber/oops"
)

// ECIESEncryptor implements TunnelEncryptor using ECIES-X25519 encryption.
// This is a thin wrapper around the existing ecies package functionality.
// It provides tunnel-level encryption for I2P's modern encryption scheme that
// replaces legacy AES-256-CBC encryption.
type ECIESEncryptor struct {
	recipientPubKey [32]byte // X25519 public key for encryption
}

// NewECIESEncryptor creates a new ECIES tunnel encryptor using the recipient's public key.
// The public key must be exactly 32 bytes (X25519 public key format).
// This encryptor will generate ephemeral keys for each encryption operation.
func NewECIESEncryptor(recipientPubKey [32]byte) *ECIESEncryptor {
	log.WithFields(map[string]interface{}{
		"operation": "create_ecies_encryptor",
		"key_type":  "x25519_public",
		"key_size":  len(recipientPubKey),
	}).Debug("Creating new ECIES tunnel encryptor")

	return &ECIESEncryptor{
		recipientPubKey: recipientPubKey,
	}
}

// Encrypt encrypts the plaintext using ECIES-X25519 scheme.
// This method wraps ecies.EncryptECIESX25519() and delegates all cryptographic
// operations to the existing ecies package.
//
// The encryption follows I2P Proposal 144 specification:
// - Generates ephemeral X25519 key pair
// - Performs X25519 key agreement with recipient's public key
// - Derives encryption key using HKDF-SHA256
// - Encrypts using ChaCha20-Poly1305 AEAD
//
// Returns ciphertext in format: [ephemeral_pubkey][nonce][aead_ciphertext]
func (e *ECIESEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		log.WithFields(map[string]interface{}{
			"operation":     "ecies_encrypt",
			"plaintext_len": 0,
			"input_type":    "nil",
		}).Debug("ECIES encrypt: handling nil plaintext")
		return ecies.EncryptECIESX25519(e.recipientPubKey[:], []byte{})
	}

	log.WithFields(map[string]interface{}{
		"operation":     "ecies_encrypt",
		"plaintext_len": len(plaintext),
		"encryption":    "x25519_chacha20poly1305",
	}).Debug("Encrypting data with ECIES-X25519")

	ciphertext, err := ecies.EncryptECIESX25519(e.recipientPubKey[:], plaintext)
	if err != nil {
		log.WithFields(map[string]interface{}{
			"operation":     "ecies_encrypt",
			"plaintext_len": len(plaintext),
			"error":         err.Error(),
		}).Error("ECIES encryption failed")
		return nil, oops.Wrapf(ErrECIESEncryptionFailed, "encryption operation failed: %w", err)
	}

	log.WithFields(map[string]interface{}{
		"operation":      "ecies_encrypt",
		"plaintext_len":  len(plaintext),
		"ciphertext_len": len(ciphertext),
		"overhead_bytes": len(ciphertext) - len(plaintext),
	}).Debug("ECIES encryption successful")
	return ciphertext, nil
}

// Decrypt decrypts the ciphertext using ECIES-X25519 scheme.
// This method wraps ecies.DecryptECIESX25519() and delegates all cryptographic
// operations to the existing ecies package.
//
// Note: For tunnel decryption, this requires the recipient's private key.
// In a real tunnel implementation, each hop would have its own private key
// for decrypting its layer of encryption.
//
// Expected ciphertext format: [ephemeral_pubkey][nonce][aead_ciphertext]
func (e *ECIESEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	// Note: This is a placeholder implementation. In practice, tunnel decryption
	// requires the private key corresponding to the public key used for encryption.
	// For the interface implementation, we return an error indicating this limitation.

	log.WithFields(map[string]interface{}{
		"operation":   "ecies_decrypt",
		"component":   "encryptor",
		"unsupported": true,
	}).Debug("ECIES decrypt called on encryptor (requires private key)")
	return nil, ErrECIESOperationNotSupported
} // Type returns the tunnel encryption type for this encryptor.
func (e *ECIESEncryptor) Type() TunnelEncryptionType {
	return TunnelEncryptionECIES
}

// ECIESDecryptor implements TunnelEncryptor using ECIES-X25519 decryption.
// This is a separate struct because decryption requires a private key.
type ECIESDecryptor struct {
	recipientPrivKey [32]byte // X25519 private key for decryption
}

// NewECIESDecryptor creates a new ECIES tunnel decryptor using the recipient's private key.
// The private key must be exactly 32 bytes (X25519 private key format).
func NewECIESDecryptor(recipientPrivKey [32]byte) *ECIESDecryptor {
	log.WithFields(map[string]interface{}{
		"operation": "create_ecies_decryptor",
		"key_type":  "x25519_private",
		"key_size":  len(recipientPrivKey),
	}).Debug("Creating new ECIES tunnel decryptor")

	return &ECIESDecryptor{
		recipientPrivKey: recipientPrivKey,
	}
}

// Encrypt is not supported by the decryptor. Returns an error.
func (d *ECIESDecryptor) Encrypt(plaintext []byte) ([]byte, error) {
	log.WithFields(map[string]interface{}{
		"operation":   "ecies_encrypt",
		"component":   "decryptor",
		"unsupported": true,
	}).Debug("ECIES encrypt called on decryptor (not supported)")
	return nil, ErrECIESOperationNotSupported
}

// Decrypt decrypts the ciphertext using ECIES-X25519 scheme with the private key.
// This method wraps ecies.DecryptECIESX25519() and delegates all cryptographic
// operations to the existing ecies package.
func (d *ECIESDecryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if ciphertext == nil {
		log.WithFields(map[string]interface{}{
			"operation":      "ecies_decrypt",
			"ciphertext_len": 0,
			"input_type":     "nil",
		}).Debug("ECIES decrypt: handling nil ciphertext")
		return nil, ErrECIESInvalidCiphertext
	}

	log.WithFields(map[string]interface{}{
		"operation":      "ecies_decrypt",
		"ciphertext_len": len(ciphertext),
		"decryption":     "x25519_chacha20poly1305",
	}).Debug("Decrypting data with ECIES-X25519")

	plaintext, err := ecies.DecryptECIESX25519(d.recipientPrivKey[:], ciphertext)
	if err != nil {
		log.WithFields(map[string]interface{}{
			"operation":      "ecies_decrypt",
			"ciphertext_len": len(ciphertext),
			"error":          err.Error(),
		}).Error("ECIES decryption failed")
		return nil, oops.Wrapf(ErrECIESDecryptionFailed, "decryption operation failed: %w", err)
	}

	log.WithFields(map[string]interface{}{
		"operation":      "ecies_decrypt",
		"ciphertext_len": len(ciphertext),
		"plaintext_len":  len(plaintext),
		"overhead_bytes": len(ciphertext) - len(plaintext),
	}).Debug("ECIES decryption successful")
	return plaintext, nil
}

// Type returns the tunnel encryption type for this decryptor.
func (d *ECIESDecryptor) Type() TunnelEncryptionType {
	return TunnelEncryptionECIES
}

// Zero securely clears the private key from memory.
func (d *ECIESDecryptor) Zero() {
	for i := range d.recipientPrivKey {
		d.recipientPrivKey[i] = 0
	}
	log.WithFields(map[string]interface{}{
		"operation":   "zero_private_key",
		"component":   "ecies_decryptor",
		"key_type":    "x25519_private",
		"key_cleared": true,
	}).Debug("ECIES decryptor private key cleared")
}
