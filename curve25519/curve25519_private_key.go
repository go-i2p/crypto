package curve25519

import (
	"github.com/go-i2p/crypto/types"
	"go.step.sm/crypto/x25519"
)

// Curve25519PrivateKey represents a Curve25519 private key for decryption and signing operations.
// This type implements the types.PrivateEncryptionKey interface and provides X25519 elliptic curve
// cryptographic operations including key derivation, decryption, and digital signature creation.
//
// CRITICAL: Always use NewCurve25519PrivateKey() to create instances.
//
// WRONG - Unsafe:
//
//	var key Curve25519PrivateKey  // Zero value - cryptographically invalid
//
// CORRECT - Use constructor:
//
//	privKey, err := curve25519.NewCurve25519PrivateKey(privBytes)
//	if err != nil {
//	    return err
//	}
//	defer privKey.Zero() // Always zero private keys
//
// Security:
//   - Private keys contain sensitive material
//   - Always call Zero() when done to clear memory
//   - Never log or transmit private keys
//   - Reject all-zero keys (cryptographically invalid)
type Curve25519PrivateKey []byte

// Bytes returns the raw byte representation of the Curve25519 private key.
// The returned slice contains the 32-byte X25519 private key material in little-endian format.
// This implements the types.PrivateKey interface for key serialization and storage operations.
func (k Curve25519PrivateKey) Bytes() []byte {
	return k // Return the byte slice representation of the private key
}

// Public derives the corresponding public key from this Curve25519 private key.
// This method implements the types.PrivateEncryptionKey interface and uses X25519 scalar multiplication
// to compute the public key point on the curve. The operation is mathematically equivalent to
// computing pubkey = privkey * basepoint on the Curve25519 elliptic curve.
// Returns ErrInvalidPrivateKey if the private key size is invalid (must be 32 bytes).
func (k Curve25519PrivateKey) Public() (types.PublicEncryptionKey, error) {
	// Create a proper x25519.PrivateKey from the byte slice
	if len(k) != x25519.PrivateKeySize {
		// Handle invalid private key length
		return nil, ErrInvalidPrivateKey
	}
	// Create a proper x25519.PrivateKey from the byte slice
	privKey := make(x25519.PrivateKey, x25519.PrivateKeySize)
	copy(privKey, k)
	// Derive the public key from the private key using X25519 scalar multiplication
	pubKey := privKey.Public() // This will return the corresponding public key
	x25519PubKey, ok := pubKey.(x25519.PublicKey)
	if !ok {
		log.Error("Failed to convert public key to x25519.PublicKey")
		return nil, ErrInvalidPrivateKey
	}
	curve25519PubKey := Curve25519PublicKey(x25519PubKey)
	return &curve25519PubKey, nil
}

// Zero securely clears the private key material from memory.
// This method implements the types.PrivateKey interface and overwrites all bytes of the private key
// with zeros to prevent sensitive cryptographic material from remaining in memory after use.
// This is essential for maintaining security in cryptographic applications.
func (k Curve25519PrivateKey) Zero() {
	// Replace the slice with zeroes for secure memory cleanup
	for i := range k {
		(k)[i] = 0
	}
}

// NewDecrypter creates a new Curve25519 decrypter for decrypting data encrypted to this private key.
// The decrypter uses X25519 elliptic curve Diffie-Hellman key exchange combined with ChaCha20-Poly1305
// AEAD decryption to provide secure decryption of data encrypted with the corresponding public key.
// Returns ErrInvalidPrivateKey if the private key size is invalid (must be 32 bytes).
func (k Curve25519PrivateKey) NewDecrypter() (types.Decrypter, error) {
	log.Debug("Creating new Curve25519 Decrypter")
	if len(k) != x25519.PrivateKeySize {
		log.Error("Invalid Curve25519 private key size")
		return nil, ErrInvalidPrivateKey
	}

	// Create a proper x25519.PrivateKey from the byte slice for cryptographic operations
	privKey := make(x25519.PrivateKey, x25519.PrivateKeySize)
	copy(privKey, k)

	return &Curve25519Decrypter{
		privateKey: privKey,
	}, nil
}

// NewSigner creates a new Curve25519 signer for creating digital signatures with this private key.
// The signer uses X25519 elliptic curve digital signature algorithms to create cryptographically
// secure signatures that can be verified using the corresponding Curve25519 public key.
// Returns ErrInvalidPrivateKey if the private key size is invalid (must be 32 bytes).
func (k Curve25519PrivateKey) NewSigner() (types.Signer, error) {
	log.Debug("Creating new Curve25519 Signer")
	if len(k) != x25519.PrivateKeySize {
		log.Error("Invalid Curve25519 private key size")
		return nil, ErrInvalidPrivateKey
	}
	return &Curve25519Signer{k: k}, nil
}

// NewCurve25519PrivateKey creates a validated Curve25519 private key from bytes.
// This is the REQUIRED constructor - do not use var declarations or direct construction.
//
// Parameters:
//   - data: Must be exactly 32 bytes (x25519.PrivateKeySize)
//
// Returns error if data length is invalid or key is all zeros.
//
// Example usage:
//
//	privKey, err := curve25519.NewCurve25519PrivateKey(privBytes)
//	if err != nil {
//	    return err
//	}
//	defer privKey.Zero() // Always zero private keys when done
func NewCurve25519PrivateKey(data []byte) (*Curve25519PrivateKey, error) {
	if len(data) != x25519.PrivateKeySize {
		log.WithField("expected_length", x25519.PrivateKeySize).
			WithField("actual_length", len(data)).
			Error("Invalid data length for Curve25519PrivateKey")
		return nil, ErrInvalidPrivateKey
	}

	// Check for all-zero key (invalid)
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		log.Error("Private key cannot be all zeros")
		return nil, ErrInvalidPrivateKey
	}

	key := Curve25519PrivateKey(make([]byte, x25519.PrivateKeySize))
	copy(key, data)
	log.Debug("Curve25519PrivateKey created successfully")
	return &key, nil
}

var _ types.PrivateEncryptionKey = &Curve25519PrivateKey{}
