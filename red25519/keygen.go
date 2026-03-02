package red25519

import (
	"crypto/rand"

	"github.com/go-i2p/crypto/common"
	"github.com/go-i2p/crypto/types"
	upstream "github.com/go-i2p/red25519"
	"github.com/samber/oops"
)

// GenerateRed25519Key generates a new Red25519 private key.
// This function creates a cryptographically secure Red25519 keypair using the system's
// random number generator. The returned private key implements the SigningPrivateKey interface.
func GenerateRed25519Key() (types.SigningPrivateKey, error) {
	_, priv, err := upstream.GenerateKey(rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate red25519 key: %w", err)
	}
	return Red25519PrivateKey(priv), nil
}

// GenerateRed25519KeyPair generates a new Red25519 key pair.
// This is the recommended API for generating Red25519 keys, returning concrete types
// directly without interface conversions.
//
// Returns:
//   - *Red25519PublicKey: The public key for Red25519 signature verification
//   - *Red25519PrivateKey: The private key for Red25519 signing (must be zeroed after use)
//   - error: Any error that occurred during key generation
//
// Example:
//
//	pubKey, privKey, err := red25519.GenerateRed25519KeyPair()
//	if err != nil {
//	    return err
//	}
//	defer privKey.Zero()
func GenerateRed25519KeyPair() (*Red25519PublicKey, *Red25519PrivateKey, error) {
	pubRaw, privRaw, err := common.GenerateKeyPair("Red25519", func() ([]byte, []byte, error) {
		pub, priv, err := upstream.GenerateKey(rand.Reader)
		return []byte(pub), []byte(priv), err
	}, log)
	if err != nil {
		return nil, nil, err
	}

	pubKey := Red25519PublicKey(pubRaw)
	privKey := Red25519PrivateKey(privRaw)

	return &pubKey, &privKey, nil
}
