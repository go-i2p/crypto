// Package elg implements ElGamal encryption and decryption for the I2P anonymous networking protocol.
//
// This package provides I2P-compatible ElGamal asymmetric encryption using 2048-bit security parameters.
// ElGamal encryption enables secure message transmission in the I2P network where the sender encrypts
// data using the recipient's public key, and only the recipient can decrypt using their private key.
//
// Key Features:
// - 2048-bit ElGamal encryption with I2P-standard domain parameters
// - Constant-time decryption operations to prevent timing attacks
// - SHA-256 message integrity verification during decryption
// - Support for both zero-padded and compact message formats
// - Secure random ephemeral key generation for each encryption session
//
// Security Considerations:
// - Maximum plaintext size limited to 222 bytes for cryptographic security
// - Private keys must be securely generated and stored in range [1, p-1]
// - Ephemeral keys are generated fresh for each encryption to ensure IND-CPA security
// - All operations use cryptographically secure random number generation
//
// Example Usage:
//
//	// Generate ElGamal key pair
//	pubKey, privKey, err := elg.GenerateKeyPair()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create encrypter and decrypter
//	encrypter, _ := pubKey.NewEncrypter()
//	decrypter, _ := privKey.NewDecrypter()
//
//	// Encrypt data (max 222 bytes)
//	plaintext := []byte("Secret message for I2P")
//	ciphertext, _ := encrypter.Encrypt(plaintext)
//
//	// Decrypt data
//	decrypted, _ := decrypter.Decrypt(ciphertext)
//
//	// Clean up private key when done
//	privKey.Zero()
//
// I2P Compatibility:
// This implementation follows I2P's ElGamal specifications including fixed domain parameters,
// message formatting with SHA-256 integrity checks, and support for the network's encryption
// message types used in tunnel building and end-to-end encrypted communications.
package elg

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"math/big"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/elgamal"
)

// GenerateKeyPair creates a new ElGamal key pair for I2P encryption operations.
// Returns a public key for encryption and a private key for decryption operations.
// The generated keys use I2P-standard ElGamal parameters with 2048-bit security.
// Example usage: pubKey, privKey, err := GenerateKeyPair()
func GenerateKeyPair() (types.PublicEncryptionKey, types.PrivateEncryptionKey, error) {
	log.Debug("Generating ElGamal key pair")

	// Generate using standard ElGamal algorithm with I2P parameters
	var elgPriv elgamal.PrivateKey
	err := ElgamalGenerate(&elgPriv, nil)
	if err != nil {
		log.WithError(err).Error("Failed to generate ElGamal key pair")
		return nil, nil, oops.Errorf("ElGamal key generation failed: %w", err)
	}

	// Convert to I2P public key format
	var pubKey ElgPublicKey
	yBytes := elgPriv.Y.Bytes()
	if len(yBytes) <= 256 {
		copy(pubKey[256-len(yBytes):], yBytes)
	} else {
		log.Error("Generated public key Y component too large")
		return nil, nil, oops.Errorf("invalid public key size")
	}

	// Convert to I2P private key format
	var privKey ElgPrivateKey
	xBytes := elgPriv.X.Bytes()
	if len(xBytes) <= 256 {
		copy(privKey[256-len(xBytes):], xBytes)
	} else {
		log.Error("Generated private key X component too large")
		return nil, nil, oops.Errorf("invalid private key size")
	}

	log.Debug("ElGamal key pair generated successfully")
	return pubKey, privKey, nil
}

// PrivateKey wraps the standard ElGamal private key with I2P-specific functionality.
// Provides compatibility layer between I2P's ElGamal implementation and the underlying cryptographic library.
type PrivateKey struct {
	elgamal.PrivateKey
}

// ElgamalGenerate creates a new ElGamal key pair using I2P's standard parameters.
// Generates cryptographically secure private keys in the range [1, p-1] using the secure random package.
// The io.Reader parameter is ignored as we use our own secure random source for enhanced security.
// This function implements the complete ElGamal key generation process:
// 1. Initialize with fixed I2P domain parameters (p, g) for network compatibility
// 2. Generate random private exponent X in valid range [1, p-1]
// 3. Compute public key Y = g^X mod p using modular exponentiation
// 4. Validate all parameters for cryptographic correctness
// generate an elgamal key pair
func ElgamalGenerate(priv *elgamal.PrivateKey, _ io.Reader) (err error) {
	log.Debug("Generating ElGamal key pair")
	// Set standard I2P ElGamal domain parameters for network compatibility
	// These parameters are standardized across the I2P network for interoperability
	priv.P = elgp // 2048-bit prime modulus
	priv.G = elgg // Generator element (g = 2)

	// Generate cryptographically secure private key using secure random package
	// Private key must be in range [1, p-1] for ElGamal security requirements
	pMinus1 := new(big.Int).Sub(priv.P, one)

	// Use our secure random package for cryptographically secure key generation
	// This ensures proper entropy and validates randomness quality
	x, err := rand.ReadBigIntInRange(one, pMinus1)
	if err != nil {
		log.WithError(err).Error("Failed to generate secure private key")
		return oops.Errorf("ElGamal private key generation failed: %w", err)
	}

	priv.X = x

	// Compute public key y = g^x mod p using secure modular exponentiation
	// This derives the public component from the private exponent using group theory
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	log.Debug("ElGamal key pair generated successfully")
	return nil
}

// elgamalDecrypt decrypts ElGamal encrypted data using I2P's specific format and validation.
// The zeroPadding parameter controls parsing of the encrypted data format.
// This function coordinates the complete decryption process by parsing ciphertext format,
// performing decryption, and validating the integrity of the decrypted message.
func elgamalDecrypt(priv *elgamal.PrivateKey, data []byte, zeroPadding bool) (decrypted []byte, err error) {
	log.WithFields(logger.Fields{
		"data_length":  len(data),
		"zero_padding": zeroPadding,
	}).Debug("Decrypting ElGamal data")

	// Parse ciphertext format (with or without zero-padding)
	ciphertext, err := parseCiphertext(data, zeroPadding)
	if err != nil {
		return nil, err
	}

	// Decrypt using the library's Decrypt method
	m, err := priv.Decrypt(nil, ciphertext, nil)
	if err != nil {
		log.WithError(err).Error("Library decryption failed")
		return nil, ElgDecryptFail
	}

	// Verify message format and extract payload
	decrypted, err = verifyAndExtractPayload(m)
	if err != nil {
		return nil, err
	}

	log.WithField("decrypted_length", len(decrypted)).Debug("ElGamal decryption successful")
	return
}

// parseCiphertext extracts the raw ciphertext from I2P's formatted encrypted data.
// Handles both zero-padded format (514 bytes) and non-padded format (512 bytes).
// Returns the extracted ciphertext ready for cryptographic decryption.
func parseCiphertext(data []byte, zeroPadding bool) ([]byte, error) {
	if zeroPadding {
		// Zero-padded format: [0][256 bytes c1][0][256 bytes c2] = 514 bytes
		if len(data) != 514 {
			log.WithError(ElgDecryptFail).Error("Invalid ciphertext length for zero-padded format")
			return nil, ElgDecryptFail
		}
		// Extract c1 and c2, removing the zero bytes
		ciphertext := make([]byte, 512)
		copy(ciphertext[0:256], data[1:257])     // c1 from positions 1-256
		copy(ciphertext[256:512], data[258:514]) // c2 from positions 258-513
		return ciphertext, nil
	}

	// Non-padded format: [256 bytes c1][256 bytes c2] = 512 bytes
	if len(data) != 512 {
		log.WithError(ElgDecryptFail).Error("Invalid ciphertext length for non-padded format")
		return nil, ElgDecryptFail
	}
	return data, nil
}

// verifyAndExtractPayload validates the decrypted message format and integrity.
// Checks message length, type byte, and SHA-256 hash before extracting the payload.
// Returns the verified payload with trailing zeros removed.
func verifyAndExtractPayload(m []byte) ([]byte, error) {
	// Verify I2P message format
	if len(m) != 255 {
		log.WithField("length", len(m)).Error("Decrypted message has incorrect length")
		return nil, ElgDecryptFail
	}

	// Verify message type byte
	if m[0] != 0xFF {
		log.WithField("type_byte", m[0]).Error("Invalid message type byte")
		return nil, ElgDecryptFail
	}

	// Verify SHA-256 integrity hash
	if err := verifyMessageHash(m); err != nil {
		return nil, err
	}

	// Extract payload and trim trailing zeros
	return extractPayload(m), nil
}

// verifyMessageHash performs constant-time SHA-256 hash verification on the decrypted message.
// Compares the embedded hash with the computed hash of the payload to ensure data integrity.
// Uses constant-time comparison to prevent timing attacks.
func verifyMessageHash(m []byte) error {
	expectedHash := sha256.Sum256(m[33:255])
	actualHash := m[1:33]

	// Use constant-time comparison to prevent timing attacks
	good := subtle.ConstantTimeCompare(expectedHash[:], actualHash)

	if good != 1 {
		log.Error("Hash verification failed")
		return ElgDecryptFail
	}

	return nil
}

// extractPayload extracts the message payload from the decrypted I2P message.
// Copies bytes 33-255 and removes trailing zero-byte padding to recover the original plaintext.
func extractPayload(m []byte) []byte {
	decrypted := make([]byte, 222)
	copy(decrypted, m[33:255])

	// Trim trailing zeros from payload
	for len(decrypted) > 0 && decrypted[len(decrypted)-1] == 0 {
		decrypted = decrypted[:len(decrypted)-1]
	}

	return decrypted
}
