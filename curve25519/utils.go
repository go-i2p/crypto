package curve25519

import (
	"crypto/rand"

	"github.com/samber/oops"

	"github.com/go-i2p/crypto/types"
	"go.step.sm/crypto/x25519"
)

// GenerateKeyPair generates a new Curve25519 key pair for encryption/decryption operations.
// Returns the public key, private key, and any error that occurred during generation.
// Moved from: curve25519.go
func GenerateKeyPair() (types.PublicEncryptionKey, types.PrivateEncryptionKey, error) {
	log.Debug("Generating new Curve25519 key pair")
	pub, priv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, oops.Errorf("failed to generate Curve25519 key pair: %w", err)
	}
	return Curve25519PublicKey(pub[:]), Curve25519PrivateKey(priv), nil
}

// IsValid checks if the provided byte slice looks kind of like a Curve25519 public key.
// It returns true if the key seems right, otherwise false.
func IsValid(key []byte) bool {
	if len(key) != x25519.PublicKeySize {
		return false
	}
	publicKey := x25519.PublicKey(key)
	// Attempt to perform scalar multiplication with the basepoint
	_, err := x25519.ScalarMult(publicKey, x25519.Basepoint)
	return err == nil
}