package curve25519

import (
	"crypto/sha256"
	"io"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Curve25519Decrypter handles Curve25519-based decryption operations.
// This type implements the types.Decrypter interface and provides X25519 elliptic curve
// decryption using ChaCha20-Poly1305 AEAD for secure data decryption in I2P network protocols.
type Curve25519Decrypter struct {
	privateKey x25519.PrivateKey // X25519 private key for ECDH key exchange and decryption
}

// Decrypt decrypts data that was encrypted using Curve25519 and ChaCha20-Poly1305 AEAD.
// The encrypted data format is either [zero padding][ephemeral_public_key][nonce][aead_ciphertext]
// (padded, the default produced by Encrypt/EncryptPadding(_, true)) or the compact
// [ephemeral_public_key][nonce][aead_ciphertext] form produced by EncryptPadding(_, false).
// The optional leading zero-padding byte is auto-detected: the padded layout is tried first and,
// if it fails to authenticate, the compact layout is tried. This method performs X25519 key
// exchange with the ephemeral public key, derives the decryption key using HKDF-SHA256, and then
// decrypts the data using ChaCha20-Poly1305 authenticated encryption. The minimum data size is
// 60 bytes (32-byte public key + 12-byte nonce + 16-byte tag), or 61 bytes when zero-padded.
func (c *Curve25519Decrypter) Decrypt(data []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "curve25519", "func": "Curve25519Decrypter.Decrypt", "data_length": len(data)}).Debug("Decrypting data with Curve25519")

	// Auto-detect the optional leading zero-padding byte. A padded message starts with 0x00, but a
	// compact message's first byte is the ephemeral public key's first byte, which is itself random
	// and may be 0x00. To disambiguate reliably, try the padded layout first and fall back to the
	// compact layout if authentication fails.
	var lastErr error
	for _, offset := range []int{1, 0} {
		plaintext, err := c.decryptAt(data, offset)
		if err == nil {
			log.WithFields(logger.Fields{"pkg": "curve25519", "func": "Curve25519Decrypter.Decrypt"}).Debug("Data decrypted successfully")
			return plaintext, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// decryptAt decrypts data assuming the given leading-padding offset (1 for the zero-padded
// format, 0 for the compact format).
func (c *Curve25519Decrypter) decryptAt(data []byte, offset int) ([]byte, error) {
	if err := c.validateDecryptionData(data, offset); err != nil {
		return nil, err
	}

	sharedSecret, err := c.deriveSharedSecret(data, offset)
	if err != nil {
		return nil, err
	}

	key, err := c.deriveDecryptionKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	return c.performAEADDecryption(data, key, offset)
}

// validateDecryptionData validates that the encrypted data has sufficient length for decryption.
func (c *Curve25519Decrypter) validateDecryptionData(data []byte, offset int) error {
	// offset is 1 for the zero-padded format, 0 for the compact format.
	// 12 is the ChaCha20-Poly1305 nonce size, 16 is the AEAD tag size.
	minSize := offset + x25519.PublicKeySize + 12 + 16
	if len(data) < minSize {
		return oops.Errorf("data too short for Curve25519 decryption: %d bytes", len(data))
	}
	return nil
}

// deriveSharedSecret extracts the ephemeral public key and derives the shared secret.
func (c *Curve25519Decrypter) deriveSharedSecret(data []byte, offset int) ([]byte, error) {
	// Skip the optional zero padding byte and extract the ephemeral public key
	ephemeralPub := data[offset : offset+x25519.PublicKeySize]

	pubKey := make(x25519.PublicKey, x25519.PublicKeySize)
	copy(pubKey, ephemeralPub)

	sharedSecret, err := c.privateKey.SharedKey(pubKey[:])
	if err != nil {
		return nil, oops.Errorf("Curve25519 key exchange failed: %w", err)
	}

	return sharedSecret, nil
}

// deriveDecryptionKey derives the decryption key from the shared secret using HKDF-SHA256.
func (c *Curve25519Decrypter) deriveDecryptionKey(sharedSecret []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ChaCha20-Poly1305"))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, oops.Errorf("failed to derive decryption key: %w", err)
	}
	return key, nil
}

// performAEADDecryption creates the AEAD cipher and performs the actual decryption.
// The offset is the leading-padding offset (1 for the zero-padded format, 0 for the compact format).
func (c *Curve25519Decrypter) performAEADDecryption(data, key []byte, offset int) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	nonceOffset := offset + x25519.PublicKeySize // Skip the optional zero padding byte and ephemeral public key
	if len(data) < nonceOffset+nonceSize {
		return nil, oops.Errorf("data too short to extract nonce")
	}

	nonce := data[nonceOffset : nonceOffset+nonceSize]
	ciphertext := data[nonceOffset+nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, oops.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}
