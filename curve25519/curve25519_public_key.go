package curve25519

import (
	"crypto/rand"

	"github.com/go-i2p/crypto/types"
	"go.step.sm/crypto/x25519"
)

// Curve25519PublicKey represents a Curve25519 public key for encryption and signature verification.
// This type implements the types.PublicEncryptionKey interface and provides X25519 elliptic curve
// cryptographic operations for I2P network encryption and ECDH key exchange protocols.
//
// CRITICAL: Always use NewCurve25519PublicKey() to create instances. Direct construction causes nil panics.
//
// WRONG - Will panic:
//
//	var key Curve25519PublicKey  // nil slice - methods will fail
//	copy(key[:], data)           // panic: copy to nil slice
//
// CORRECT - Use constructor:
//
//	key, err := curve25519.NewCurve25519PublicKey(data)
//	if err != nil {
//	    return err
//	}
//
// Deprecated patterns (avoid in new code):
//
//	x25519Key := CreateCurve25519PublicKey(data)  // Use NewCurve25519PublicKey instead
type Curve25519PublicKey []byte

// Bytes returns the raw byte representation of the Curve25519 public key.
// The returned slice contains the 32-byte X25519 public key material in little-endian format
// suitable for cryptographic operations and network transmission.
func (k Curve25519PublicKey) Bytes() []byte {
	return k
}

// NewVerifier creates a Curve25519 verifier for signature verification operations.
// This method validates the public key size and returns a verifier instance capable of verifying
// signatures created with the corresponding Curve25519 private key using X25519 signature algorithms.
// Returns ErrInvalidPublicKey if the key size is invalid (must be 32 bytes).
func (k Curve25519PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating Curve25519 verifier")
	if len(k) != x25519.PublicKeySize {
		log.Error("Invalid public key size")
		return nil, ErrInvalidPublicKey
	}
	return &Curve25519Verifier{k: k}, nil
}

// Len returns the length of the Curve25519 public key in bytes.
// For X25519 public keys, this will always return 32 bytes as defined by the curve specification.
// This method is used for key validation and buffer allocation in cryptographic operations.
func (k Curve25519PublicKey) Len() int {
	length := len(k)
	log.WithField("length", length).Debug("Retrieved Curve25519PublicKey length")
	return length
}

// NewEncrypter creates a new Curve25519 encrypter for encrypting data to this public key.
// The encrypter uses X25519 elliptic curve Diffie-Hellman key exchange combined with ChaCha20-Poly1305
// AEAD encryption to provide secure encryption suitable for I2P network protocols.
// Returns ErrInvalidPublicKey if the key size is invalid (must be 32 bytes).
func (k Curve25519PublicKey) NewEncrypter() (types.Encrypter, error) {
	log.Debug("Creating new Curve25519 Encrypter")

	if len(k) != x25519.PublicKeySize {
		log.Error("Invalid public key size")
		return nil, ErrInvalidPublicKey
	}

	// Create a proper x25519.PublicKey from the byte slice for cryptographic operations
	pubKey := make(x25519.PublicKey, x25519.PublicKeySize)
	copy(pubKey, k)

	enc, err := NewCurve25519Encryption(&pubKey, rand.Reader)
	if err != nil {
		log.WithError(err).Error("Failed to create Curve25519 Encrypter")
		return nil, err
	}

	log.Debug("Curve25519 Encrypter created successfully")
	return enc, nil
}

// NewCurve25519PublicKey creates a validated Curve25519 public key from bytes.
// This is the REQUIRED constructor - do not use var declarations or direct construction.
//
// Parameters:
//   - data: Must be exactly 32 bytes (x25519.PublicKeySize)
//
// Returns error if data length is invalid.
//
// Example usage:
//
//	pubKey, err := curve25519.NewCurve25519PublicKey(pubBytes)
//	if err != nil {
//	    return err
//	}
func NewCurve25519PublicKey(data []byte) (*Curve25519PublicKey, error) {
	if len(data) != x25519.PublicKeySize {
		log.WithField("expected_length", x25519.PublicKeySize).
			WithField("actual_length", len(data)).
			Error("Invalid data length for Curve25519PublicKey")
		return nil, ErrInvalidPublicKey
	}
	key := Curve25519PublicKey(make([]byte, x25519.PublicKeySize))
	copy(key, data)
	log.Debug("Curve25519PublicKey created successfully")
	return &key, nil
}

// CreateCurve25519PublicKey creates a Curve25519 public key from raw byte data.
// This function validates the input data length and constructs a proper X25519 public key.
// The data must be exactly 32 bytes to match the X25519 public key size specification.
// Returns nil if the input data length is invalid, otherwise returns a pointer to the created key.
//
// Deprecated: Use NewCurve25519PublicKey instead. This function will be removed in v2.0.
func CreateCurve25519PublicKey(data []byte) (k *x25519.PublicKey) {
	log.Warn("CreateCurve25519PublicKey is deprecated, use NewCurve25519PublicKey")
	log.WithField("data_length", len(data)).Debug("Creating Curve25519PublicKey")
	key, err := NewCurve25519PublicKey(data)
	if err != nil {
		return nil
	}
	x25519Key := x25519.PublicKey(*key)
	return &x25519Key
}

var _ types.PublicEncryptionKey = &Curve25519PublicKey{}
