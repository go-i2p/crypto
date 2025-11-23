package curve25519

import (
	"crypto/rand"

	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

// GenerateX25519KeyPair generates a new Curve25519 (X25519) key pair for encryption.
// This is the recommended API for generating X25519 keys, returning concrete types
// directly without interface conversions.
//
// Returns:
//   - *Curve25519PublicKey: The public key for encryption
//   - *Curve25519PrivateKey: The private key for decryption (must be zeroed after use)
//   - error: Any error that occurred during key generation
//
// Example:
//
//	pubKey, privKey, err := curve25519.GenerateX25519KeyPair()
//	if err != nil {
//	    return err
//	}
//	defer privKey.Zero()  // Securely clear private key when done
//
//	// Use keys directly without type assertions
//	encrypter, _ := pubKey.NewEncrypter()
//	ciphertext, _ := encrypter.Encrypt(plaintext)
func GenerateX25519KeyPair() (*Curve25519PublicKey, *Curve25519PrivateKey, error) {
	log.Debug("Generating Curve25519 (X25519) key pair")

	// Generate using X25519 library
	pubKeyRaw, privKeyRaw, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, oops.Errorf("failed to generate X25519 key pair: %w", err)
	}

	// Convert to our concrete types
	pubKey := Curve25519PublicKey(pubKeyRaw[:])
	privKey := Curve25519PrivateKey(privKeyRaw)

	log.WithField("pubkey_len", len(pubKey)).
		WithField("privkey_len", len(privKey)).
		Debug("X25519 key pair generated successfully")

	return &pubKey, &privKey, nil
}
