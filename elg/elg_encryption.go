package elg

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/go-i2p/elgamal"
)

// ElgamalEncryption represents an ElGamal encryption wrapper using the go-i2p/elgamal library.
// It wraps a PublicKey and provides I2P-specific message formatting with SHA-256 integrity checks.
type ElgamalEncryption struct {
	pub *elgamal.PublicKey
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
// This method coordinates the I2P ElGamal encryption process.
func (elg *ElgamalEncryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Encrypting data with ElGamal padding")

	// Validate data size limit for ElGamal security constraints
	if len(data) > 222 {
		return nil, ElgEncryptTooBig
	}

	// Prepare and hash the message block
	mbytes := prepareMessageBlock(data)

	// Encrypt using the library's Encrypt method
	ciphertext, err := elg.pub.Encrypt(rand.Reader, mbytes)
	if err != nil {
		log.WithError(err).Error("Failed to encrypt with ElGamal")
		return nil, err
	}

	// Format output according to padding requirements
	encrypted = formatCiphertext(ciphertext, zeroPadding)

	log.WithField("encrypted_length", len(encrypted)).Debug("Data encrypted successfully with ElGamal")
	return
}

// prepareMessageBlock creates an I2P-formatted message block with SHA-256 integrity hash.
// Structure: [0xFF][32-byte SHA-256 hash][222-byte payload]
func prepareMessageBlock(data []byte) []byte {
	mbytes := make([]byte, 255)
	mbytes[0] = 0xFF        // I2P message type indicator
	copy(mbytes[33:], data) // Copy payload starting at byte 33

	// Compute SHA-256 integrity hash of the payload data (full 222 bytes)
	d := sha256.Sum256(mbytes[33:255])
	copy(mbytes[1:], d[:]) // Insert hash at bytes 1-32

	return mbytes
}

// formatCiphertext formats the ElGamal ciphertext according to I2P protocol requirements.
// Returns either zero-padded format (514 bytes) or compact format (512 bytes).
func formatCiphertext(ciphertext []byte, zeroPadding bool) []byte {
	if zeroPadding {
		// Zero-padded format: [1 zero byte][256-byte c1][1 zero byte][256-byte c2]
		encrypted := make([]byte, 514)
		copy(encrypted[1:257], ciphertext[0:256])     // Insert c1 at offset 1
		copy(encrypted[258:514], ciphertext[256:512]) // Insert c2 at offset 258
		return encrypted
	}

	// Compact format: [256-byte c1][256-byte c2] without padding
	return ciphertext
}

// createElgamalEncryption initializes a new ElGamal encryption wrapper.
// Returns an encryption session that uses the go-i2p/elgamal library for all operations.
func createElgamalEncryption(pub *elgamal.PublicKey) (enc *ElgamalEncryption, err error) {
	log.Debug("Creating ElGamal encryption session")
	if pub == nil {
		log.Error("Cannot create encrypter with nil public key")
		return nil, ElgEncryptTooBig // TODO: create proper error
	}
	enc = &ElgamalEncryption{
		pub: pub,
	}
	log.Debug("ElGamal encryption session created successfully")
	return
}
