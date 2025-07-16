package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// GenerateEd25519Key generates a new Ed25519 private key for digital signatures.
// This function creates a cryptographically secure Ed25519 keypair using the system's
// random number generator. The returned private key implements the SigningPrivateKey interface.
// Example usage: privKey, err := GenerateEd25519Key()
// GenerateEd25519Key generates a new Ed25519 private key for digital signatures.
// Returns a private key that implements the SigningPrivateKey interface.
// Moved from: ed25519.go
func GenerateEd25519Key() (types.SigningPrivateKey, error) {
	// Generate secure random Ed25519 keypair using crypto/rand
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate ed25519")
	}
	return Ed25519PrivateKey(priv), nil
}
