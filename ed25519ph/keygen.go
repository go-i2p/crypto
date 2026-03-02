package ed25519ph

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/go-i2p/crypto/common"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// GenerateEd25519phKey generates a new Ed25519 private key for Ed25519ph signatures.
// This function creates a cryptographically secure Ed25519 keypair using the system's
// random number generator. The returned private key implements the SigningPrivateKey interface
// and produces Ed25519ph (pre-hashed) signatures with domain separation per RFC 8032.
func GenerateEd25519phKey() (types.SigningPrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate ed25519ph key")
	}
	return Ed25519phPrivateKey(priv), nil
}

// GenerateEd25519phKeyPair generates a new Ed25519 key pair for Ed25519ph signatures.
// This is the recommended API for generating Ed25519ph keys, returning concrete types
// directly without interface conversions.
//
// Returns:
//   - *Ed25519phPublicKey: The public key for Ed25519ph signature verification
//   - *Ed25519phPrivateKey: The private key for Ed25519ph signing (must be zeroed after use)
//   - error: Any error that occurred during key generation
//
// Example:
//
//	pubKey, privKey, err := ed25519ph.GenerateEd25519phKeyPair()
//	if err != nil {
//	    return err
//	}
//	defer privKey.Zero()
func GenerateEd25519phKeyPair() (*Ed25519phPublicKey, *Ed25519phPrivateKey, error) {
	pubRaw, privRaw, err := common.GenerateKeyPair("Ed25519ph", func() ([]byte, []byte, error) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		return []byte(pub), []byte(priv), err
	}, log)
	if err != nil {
		return nil, nil, err
	}

	pubKey := Ed25519phPublicKey(pubRaw)
	privKey := Ed25519phPrivateKey(privRaw)

	return &pubKey, &privKey, nil
}
