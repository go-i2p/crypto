package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/go-i2p/crypto/common"
)

// GenerateEd25519KeyPair generates a new Ed25519 key pair for digital signatures.
// This is the recommended API for generating Ed25519 keys, returning concrete types
// directly without interface conversions.
//
// Returns:
//   - *Ed25519PublicKey: The public key for signature verification
//   - *Ed25519PrivateKey: The private key for signing (must be zeroed after use)
//   - error: Any error that occurred during key generation
//
// Example:
//
//	pubKey, privKey, err := ed25519.GenerateEd25519KeyPair()
//	if err != nil {
//	    return err
//	}
//	defer privKey.Zero()  // Securely clear private key when done
//
//	// Use keys directly without type assertions
//	signer, _ := privKey.NewSigner()
//	signature, _ := signer.Sign(data)
func GenerateEd25519KeyPair() (*Ed25519PublicKey, *Ed25519PrivateKey, error) {
	pubRaw, privRaw, err := common.GenerateKeyPair("Ed25519", func() ([]byte, []byte, error) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		return []byte(pub), []byte(priv), err
	}, log)
	if err != nil {
		return nil, nil, err
	}

	pubKey := Ed25519PublicKey(pubRaw)
	privKey := Ed25519PrivateKey(privRaw)

	return &pubKey, &privKey, nil
}
