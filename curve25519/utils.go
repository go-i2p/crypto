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
