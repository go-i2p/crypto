// Package chacha20poly1305 provides ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)
// for the I2P (Invisible Internet Project) anonymous networking ecosystem.
//
// This package implements the IETF ChaCha20-Poly1305 AEAD construction as defined in RFC 8439,
// combining the ChaCha20 stream cipher with the Poly1305 MAC for authenticated encryption.
// This is the modern encryption standard for I2P tunnel and garlic message encryption.
//
// # Key Features
//
//   - Authenticated encryption preventing message tampering
//   - High performance on modern CPUs (faster than AES on systems without AES-NI)
//   - Constant-time implementation resistant to timing attacks
//   - Support for additional authenticated data (AAD)
//
// # Usage Example
//
//	// Generate a random key
//	key, _ := chacha20poly1305.GenerateKey()
//
//	// Create AEAD cipher
//	aead, _ := chacha20poly1305.NewAEAD(key)
//
//	// Encrypt with associated data
//	plaintext := []byte("Secret message")
//	associatedData := []byte("public metadata")
//	nonce := make([]byte, chacha20poly1305.NonceSize)
//	rand.Read(nonce)
//
//	ciphertext, tag, _ := aead.Encrypt(plaintext, associatedData, nonce)
//
//	// Decrypt and verify
//	decrypted, _ := aead.Decrypt(ciphertext, tag, associatedData, nonce)
//
// # Security Considerations
//
//   - Never reuse a nonce with the same key - this breaks authentication
//   - Generate nonces using a cryptographically secure random number generator
//   - Use unique keys for different encryption contexts
//   - Verify the authentication tag before processing decrypted data
//
// # I2P Protocol Integration
//
// This package is used for:
//   - Garlic message encryption (ECIES-X25519-AEAD-Ratchet)
//   - Tunnel layer encryption
//   - Session-based messaging with forward secrecy
package chacha20poly1305

import (
	"crypto/cipher"

	stdchacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/go-i2p/crypto/rand"
	"github.com/samber/oops"
)

// AEAD provides ChaCha20-Poly1305 authenticated encryption with associated data.
// This cipher combines the ChaCha20 stream cipher with the Poly1305 MAC to provide
// both confidentiality and authenticity for encrypted messages.
//
// The AEAD cipher is safe for concurrent use by multiple goroutines.
type AEAD struct {
	cipher cipher.AEAD
}

// NewAEAD creates a new ChaCha20-Poly1305 AEAD cipher with the given key.
// The key must be exactly 32 bytes long.
//
// Parameters:
//   - key: A 32-byte ChaCha20-Poly1305 key
//
// Returns:
//   - *AEAD: The initialized AEAD cipher
//   - error: ErrInvalidKeySize if the key is not 32 bytes
//
// Example:
//
//	key := [32]byte{...}  // Your 32-byte key
//	aead, err := NewAEAD(key)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewAEAD(key [KeySize]byte) (*AEAD, error) {
	log.Debug("Creating new ChaCha20-Poly1305 AEAD cipher")

	cipher, err := stdchacha.New(key[:])
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create ChaCha20-Poly1305 cipher")
	}

	return &AEAD{cipher: cipher}, nil
}

// Encrypt encrypts plaintext with associated data using ChaCha20-Poly1305 AEAD.
// The associated data is authenticated but not encrypted - it's useful for metadata
// that must be verified but doesn't need confidentiality.
//
// Parameters:
//   - plaintext: The data to encrypt
//   - associatedData: Additional data to authenticate (can be nil)
//   - nonce: A 12-byte nonce (must be unique for each encryption with the same key)
//
// Returns:
//   - ciphertext: The encrypted data (same length as plaintext)
//   - tag: The 16-byte Poly1305 authentication tag
//   - error: Any error during encryption (e.g., invalid nonce size)
//
// Security: Never reuse a nonce with the same key. This breaks the authentication
// guarantee and can leak information about the plaintext.
//
// Example:
//
//	plaintext := []byte("Secret message")
//	aad := []byte("public header")
//	nonce := make([]byte, chacha20poly1305.NonceSize)
//	rand.Read(nonce)
//
//	ciphertext, tag, err := aead.Encrypt(plaintext, aad, nonce)
func (a *AEAD) Encrypt(plaintext, associatedData, nonce []byte) (ciphertext []byte, tag [TagSize]byte, err error) {
	if len(nonce) != NonceSize {
		return nil, tag, ErrInvalidNonceSize
	}

	log.WithField("plaintext_len", len(plaintext)).
		WithField("aad_len", len(associatedData)).
		Debug("Encrypting with ChaCha20-Poly1305")

	// The golang.org/x/crypto ChaCha20-Poly1305 AEAD appends the tag to the ciphertext
	sealed := a.cipher.Seal(nil, nonce, plaintext, associatedData)

	// Split ciphertext and tag
	// sealed = ciphertext || tag
	if len(sealed) < TagSize {
		return nil, tag, oops.Errorf("encryption produced invalid output")
	}

	ciphertext = sealed[:len(sealed)-TagSize]
	copy(tag[:], sealed[len(sealed)-TagSize:])

	log.WithField("ciphertext_len", len(ciphertext)).
		Debug("Encryption successful")

	return ciphertext, tag, nil
}

// Decrypt decrypts ciphertext and verifies the authentication tag using ChaCha20-Poly1305.
// If the tag verification fails, this method returns ErrAuthenticationFailed and the
// ciphertext should be discarded as it may have been tampered with.
//
// Parameters:
//   - ciphertext: The encrypted data
//   - tag: The 16-byte Poly1305 authentication tag
//   - associatedData: The same associated data used during encryption
//   - nonce: The same 12-byte nonce used during encryption
//
// Returns:
//   - plaintext: The decrypted data (only valid if error is nil)
//   - error: ErrAuthenticationFailed if verification fails, other errors for invalid inputs
//
// Security: Always check the error before using the plaintext. If authentication fails,
// the plaintext MUST be discarded as the message may have been tampered with.
//
// Example:
//
//	plaintext, err := aead.Decrypt(ciphertext, tag, aad, nonce)
//	if err != nil {
//	    // Authentication failed - ciphertext was tampered with
//	    return err
//	}
//	// Safe to use plaintext
func (a *AEAD) Decrypt(ciphertext, tag []byte, associatedData, nonce []byte) (plaintext []byte, err error) {
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonceSize
	}

	if len(tag) != TagSize {
		return nil, oops.Errorf("invalid tag size: expected %d, got %d", TagSize, len(tag))
	}

	log.WithField("ciphertext_len", len(ciphertext)).
		WithField("aad_len", len(associatedData)).
		Debug("Decrypting with ChaCha20-Poly1305")

	// Reconstruct the sealed format: ciphertext || tag
	sealed := make([]byte, len(ciphertext)+len(tag))
	copy(sealed, ciphertext)
	copy(sealed[len(ciphertext):], tag)

	// Decrypt and verify
	plaintext, err = a.cipher.Open(nil, nonce, sealed, associatedData)
	if err != nil {
		log.WithError(err).Warn("ChaCha20-Poly1305 authentication failed")
		return nil, ErrAuthenticationFailed
	}

	log.WithField("plaintext_len", len(plaintext)).
		Debug("Decryption successful")

	return plaintext, nil
}

// GenerateKey creates a new random 32-byte ChaCha20-Poly1305 key using a
// cryptographically secure random number generator.
//
// Returns:
//   - [32]byte: A random key suitable for use with NewAEAD
//   - error: Any error from the random number generator
//
// Example:
//
//	key, err := chacha20poly1305.GenerateKey()
//	if err != nil {
//	    return err
//	}
//	aead, _ := chacha20poly1305.NewAEAD(key)
func GenerateKey() ([KeySize]byte, error) {
	var key [KeySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, oops.Wrapf(err, "failed to generate ChaCha20-Poly1305 key")
	}
	return key, nil
}

// GenerateNonce creates a new random 12-byte nonce suitable for use with ChaCha20-Poly1305.
// Each nonce must be unique for a given key - never reuse a nonce with the same key.
//
// Returns:
//   - [12]byte: A random nonce
//   - error: Any error from the random number generator
//
// Example:
//
//	nonce, err := chacha20poly1305.GenerateNonce()
//	if err != nil {
//	    return err
//	}
//	ciphertext, tag, _ := aead.Encrypt(plaintext, aad, nonce[:])
func GenerateNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, oops.Wrapf(err, "failed to generate ChaCha20-Poly1305 nonce")
	}
	return nonce, nil
}
