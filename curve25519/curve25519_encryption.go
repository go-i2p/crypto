package curve25519

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Curve25519Encryption handles Curve25519-based encryption operations.
// This type provides X25519 elliptic curve encryption using ChaCha20-Poly1305 AEAD
// for secure data encryption in I2P network protocols with ephemeral key exchange.
type Curve25519Encryption struct {
	publicKey x25519.PublicKey  // Recipient's public key for encryption
	ephemeral x25519.PrivateKey // Ephemeral private key for ECDH key exchange
}

// Encrypt encrypts data using Curve25519 and ChaCha20-Poly1305 with automatic zero padding.
// This method provides a simplified interface for encryption operations with default padding enabled.
// The maximum data size is 1024 bytes to support I2P tunnel build records and network protocols.
// Returns encrypted data in format: [zero_padding][ephemeral_pubkey][nonce][aead_ciphertext]
func (c *Curve25519Encryption) Encrypt(data []byte) ([]byte, error) {
	return c.EncryptPadding(data, true)
}

// EncryptPadding encrypts data using Curve25519 and ChaCha20-Poly1305 with optional zero padding.
// This method performs X25519 key exchange with the recipient's public key, derives an encryption key
// using HKDF-SHA256, and encrypts the data using ChaCha20-Poly1305 authenticated encryption.
// The zeroPadding parameter controls whether to prepend a zero byte to the output format.
// Maximum data size is 1024 bytes to support I2P tunnel data minus overhead requirements.
func (c *Curve25519Encryption) EncryptPadding(data []byte, zeroPadding bool) ([]byte, error) {
	if err := c.validateDataSize(data); err != nil {
		return nil, err
	}

	sharedSecret, err := c.deriveSharedSecret()
	if err != nil {
		return nil, err
	}

	key, err := c.deriveEncryptionKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	aead, err := c.createAEADCipher(key)
	if err != nil {
		return nil, err
	}

	nonce, err := c.generateNonce(aead)
	if err != nil {
		return nil, err
	}

	ciphertext := c.encryptWithAEAD(aead, nonce, data)

	return c.formatCiphertext(ciphertext, nonce, zeroPadding), nil
}

// validateDataSize checks if the data size is within I2P tunnel limits.
func (c *Curve25519Encryption) validateDataSize(data []byte) error {
	// Maximum data size is 1024 bytes to support I2P tunnel build records
	// This allows for tunnel data (1028 bytes) minus overhead
	if len(data) > 1024 {
		return ErrDataTooBig
	}
	return nil
}

// deriveSharedSecret performs X25519 Elliptic Curve Diffie-Hellman key exchange.
func (c *Curve25519Encryption) deriveSharedSecret() ([]byte, error) {
	sharedSecret, err := c.ephemeral.SharedKey(c.publicKey)
	if err != nil {
		return nil, oops.Errorf("failed to derive shared secret: %w", err)
	}
	return sharedSecret, nil
}

// deriveEncryptionKey derives encryption key using HKDF-SHA256 key derivation function.
func (c *Curve25519Encryption) deriveEncryptionKey(sharedSecret []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ChaCha20-Poly1305"))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, oops.Errorf("failed to derive encryption key: %w", err)
	}
	return key, nil
}

// createAEADCipher creates ChaCha20-Poly1305 AEAD cipher for authenticated encryption.
func (c *Curve25519Encryption) createAEADCipher(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}
	return aead, nil
}

// generateNonce creates cryptographically secure random nonce for encryption.
func (c *Curve25519Encryption) generateNonce(aead cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, oops.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// encryptWithAEAD encrypts data using ChaCha20-Poly1305 authenticated encryption.
func (c *Curve25519Encryption) encryptWithAEAD(aead cipher.AEAD, nonce, data []byte) []byte {
	return aead.Seal(nil, nonce, data, nil)
}

// formatCiphertext formats the final ciphertext with ephemeral key, nonce, and optional zero padding.
func (c *Curve25519Encryption) formatCiphertext(ciphertext, nonce []byte, zeroPadding bool) []byte {
	ephemeralPub := c.ephemeral.Public().(x25519.PublicKey)
	totalSize := x25519.PublicKeySize + len(nonce) + len(ciphertext)
	if zeroPadding {
		totalSize++ // Add 1 byte for zero padding
	}

	// Build result directly with correct size for optimal memory usage
	result := make([]byte, totalSize)
	offset := 0

	if zeroPadding {
		// Add a zero byte prefix if requested for protocol compatibility
		result[0] = 0x00
		offset = 1
	}

	// Format output as: [ephemeral public key][nonce][ciphertext]
	copy(result[offset:], ephemeralPub)
	offset += x25519.PublicKeySize
	copy(result[offset:], nonce)
	offset += len(nonce)
	copy(result[offset:], ciphertext)

	return result
}

// NewCurve25519Encryption creates a new Curve25519 encryption instance for encrypting data.
// This function generates an ephemeral key pair and prepares the encryption context for secure
// communication with the provided recipient public key. The ephemeral key provides forward secrecy
// ensuring that encrypted data cannot be decrypted even if long-term keys are compromised.
// Returns ErrInvalidPublicKey if the public key is nil or has invalid size (must be 32 bytes).
func NewCurve25519Encryption(pub *x25519.PublicKey, rand io.Reader) (*Curve25519Encryption, error) {
	if pub == nil || len(*pub) != x25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}

	// Generate ephemeral key pair for forward secrecy in encryption operations
	_, ephemeralPriv, err := x25519.GenerateKey(rand)
	if err != nil {
		return nil, oops.Errorf("failed to generate ephemeral key: %w", err)
	}

	return &Curve25519Encryption{
		publicKey: *pub,
		ephemeral: ephemeralPriv,
	}, nil
}
