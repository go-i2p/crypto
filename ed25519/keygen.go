package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/samber/oops"
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
	log.Debug("Generating Ed25519 key pair")

	// Generate using standard library
	pubKeyRaw, privKeyRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, oops.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	// Convert to our concrete types
	pubKey := Ed25519PublicKey(pubKeyRaw)
	privKey := Ed25519PrivateKey(privKeyRaw)

	log.WithField("pubkey_len", len(pubKey)).
		WithField("privkey_len", len(privKey)).
		Debug("Ed25519 key pair generated successfully")

	return &pubKey, &privKey, nil
}
