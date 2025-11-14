package elg

import (
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/go-i2p/elgamal"
	"github.com/go-i2p/logger"
)

// ElgamalEncryption represents an ElGamal encryption session with precomputed parameters.
// It stores the necessary cryptographic parameters (p, a, b1) for efficient encryption operations.
// Multiple messages can be encrypted using the same session for performance optimization.
// This structure implements a stateful ElGamal encryption session where the ephemeral
// key k is generated once and reused for multiple encryptions, providing better performance
// while maintaining cryptographic security through parameter isolation.
type ElgamalEncryption struct {
	// p stores the ElGamal prime modulus defining the finite field for all operations
	p *big.Int
	// a represents the first ElGamal ciphertext component (a = g^k mod p)
	// where k is the ephemeral key generated during session initialization
	a *big.Int
	// b1 represents the precomputed value (b1 = y^k mod p) used to encrypt messages
	// where y is the recipient's public key and k is the session ephemeral key
	b1 *big.Int
}

// Encrypt encrypts data using ElGamal with zero padding enabled by default.
// Provides a simple interface for standard ElGamal encryption operations.
// Returns encrypted data or error if encryption fails or data is too large (>222 bytes).
// This method applies I2P's standard ElGamal message format with SHA-256 integrity
// protection and automatic zero-padding for network protocol compatibility.
func (elg *ElgamalEncryption) Encrypt(data []byte) (enc []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Encrypting data with ElGamal")
	// Use zero padding by default for I2P network message compatibility
	return elg.EncryptPadding(data, true)
}

// EncryptPadding encrypts data using ElGamal with configurable padding options.
// The zeroPadding parameter controls whether to apply zero-padding for data shorter than block size.
// Maximum supported data size is 222 bytes due to ElGamal security requirements.
// This method implements the complete I2P ElGamal encryption process including:
// 1. Data size validation (max 222 bytes for security)
// 2. Message formatting with 0xFF prefix and SHA-256 integrity hash
// 3. ElGamal encryption using precomputed session parameters
// 4. Output formatting according to I2P protocol specifications
func (elg *ElgamalEncryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error) {
	log.WithFields(logger.Fields{
		"data_length":  len(data),
		"zero_padding": zeroPadding,
	}).Debug("Encrypting data with ElGamal padding")

	// Validate data size limit for ElGamal security constraints
	// ElGamal can only encrypt data smaller than the modulus due to mathematical limitations
	if len(data) > 222 {
		err = ElgEncryptTooBig
		return
	}

	// Prepare message block with I2P standard format
	// Structure: [0xFF][32-byte SHA-256 hash][222-byte payload]
	mbytes := make([]byte, 255)
	mbytes[0] = 0xFF        // I2P message type indicator
	copy(mbytes[33:], data) // Copy payload starting at byte 33

	// Compute SHA-256 integrity hash of the payload data
	// This provides cryptographic integrity verification during decryption
	d := sha256.Sum256(mbytes[33 : len(data)+33])
	copy(mbytes[1:], d[:]) // Insert hash at bytes 1-32

	// Convert message to big integer for ElGamal mathematical operations
	m := new(big.Int).SetBytes(mbytes)

	// Perform ElGamal encryption using precomputed session parameters
	// Compute second ciphertext component: b = m * y^k mod p = m * b1 mod p
	b := new(big.Int).Mod(new(big.Int).Mul(elg.b1, m), elg.p).Bytes()

	// Format output according to I2P ElGamal message structure
	// The output contains both ciphertext components (a, b) in the expected byte layout
	// Zero padding adds extra bytes for protocol compatibility and message alignment
	if zeroPadding {
		// Zero-padded format: [1 zero byte][256-byte a][1 zero byte][256-byte b]
		encrypted = make([]byte, 514)
		copy(encrypted[1:], elg.a.Bytes()) // Insert a component at offset 1
		copy(encrypted[258:], b)           // Insert b component at offset 258
	} else {
		// Compact format: [256-byte a][256-byte b] without padding
		encrypted = make([]byte, 512)
		copy(encrypted, elg.a.Bytes()) // Insert a component at start
		copy(encrypted[256:], b)       // Insert b component at offset 256
	}

	log.WithField("encrypted_length", len(encrypted)).Debug("Data encrypted successfully with ElGamal")
	return
}

// createElgamalEncryption initializes a new ElGamal encryption session with precomputed parameters.
// Generates a random ephemeral key k and precomputes a = g^k mod p and b1 = y^k mod p for efficiency.
// Multiple encryptions can reuse these parameters for better performance.
// This function implements secure ephemeral key generation with the following steps:
// 1. Generate cryptographically random 256-byte ephemeral key k
// 2. Ensure k is non-zero and within valid range [1, p-1]
// 3. Precompute session parameters a and b1 for encryption efficiency
// 4. Return initialized encryption session ready for message processing
// create a new elgamal encryption session
func createElgamalEncryption(pub *elgamal.PublicKey, rand io.Reader) (enc *ElgamalEncryption, err error) {
	log.Debug("Creating ElGamal encryption session")
	// Generate cryptographically secure ephemeral key k
	// The ephemeral key must be non-zero and less than the prime modulus p for security
	kbytes := make([]byte, 256)
	k := new(big.Int)
	for err == nil {
		// Read random bytes from secure entropy source
		_, err = io.ReadFull(rand, kbytes)
		k = new(big.Int).SetBytes(kbytes)
		k = k.Mod(k, pub.P) // Reduce modulo p to ensure valid range

		// Ensure k is not zero for cryptographic security
		// Zero ephemeral key would compromise ElGamal encryption security
		if k.Sign() != 0 {
			break
		}
	}
	if err == nil {
		// Initialize encryption session with precomputed parameters
		enc = &ElgamalEncryption{
			p:  pub.P,                             // Prime modulus
			a:  new(big.Int).Exp(pub.G, k, pub.P), // a = g^k mod p
			b1: new(big.Int).Exp(pub.Y, k, pub.P), // b1 = y^k mod p
		}
		log.Debug("ElGamal encryption session created successfully")
	} else {
		log.WithError(err).Error("Failed to create ElGamal encryption session")
	}
	return
}
