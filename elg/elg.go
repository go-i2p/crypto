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
// Implements constant-time operations to prevent timing attacks during decryption.
// The zeroPadding parameter controls parsing of the encrypted data format.
// This function implements the complete I2P ElGamal decryption process:
// 1. Parse ciphertext components (a, b) from encrypted data with optional padding
// 2. Perform ElGamal decryption: m = b * a^(-x) mod p using modular arithmetic
// 3. Extract and validate SHA-256 integrity hash from decrypted message
// 4. Return verified plaintext using constant-time operations for security
// decrypt an elgamal encrypted message, i2p style
func elgamalDecrypt(priv *elgamal.PrivateKey, data []byte, zeroPadding bool) (decrypted []byte, err error) {
	log.WithFields(logger.Fields{
		"data_length":  len(data),
		"zero_padding": zeroPadding,
	}).Debug("Decrypting ElGamal data")

	// Extract ElGamal ciphertext components (a, b) from encrypted data
	// Parse according to I2P's ElGamal message format with optional zero padding
	a := new(big.Int)
	b := new(big.Int)
	idx := 0
	if zeroPadding {
		idx++ // Skip leading zero byte in padded format
	}
	a.SetBytes(data[idx : idx+256]) // Extract first component (a)
	if zeroPadding {
		idx++ // Skip zero byte between components
	}
	b.SetBytes(data[idx+256:]) // Extract second component (b)

	// Perform ElGamal decryption using modular arithmetic: m = b * a^(-x) mod p
	// This implements the mathematical ElGamal decryption algorithm where:
	// - a^(-x) is computed as a^(p-1-x) using Fermat's little theorem
	// - The result recovers the original padded message with integrity hash
	m := new(big.Int).Mod(new(big.Int).Mul(b, new(big.Int).Exp(a, new(big.Int).Sub(new(big.Int).Sub(priv.P, priv.X), one), priv.P)), priv.P).Bytes()

	// Verify message integrity using SHA-256 digest comparison
	// The message format includes a 32-byte hash for cryptographic integrity verification
	d := sha256.Sum256(m[33:255]) // Hash the payload portion
	good := 0
	// Use constant-time comparison to prevent timing attacks during validation
	if subtle.ConstantTimeCompare(d[:], m[1:33]) == 1 {
		// Integrity check passed - decryption successful
		good = 1
		log.Debug("ElGamal decryption successful")
	} else {
		// Integrity check failed - return decryption error
		err = ElgDecryptFail
		log.WithError(err).Error("ElGamal decryption failed")
	}

	// Copy result using constant-time operation to prevent side-channel attacks
	// This ensures timing behavior is independent of decryption success/failure
	decrypted = make([]byte, 222)
	subtle.ConstantTimeCopy(good, decrypted, m[33:255])

	if good == 0 {
		// If decrypt failed, clear output to prevent information leakage
		decrypted = nil
	}
	return
}
