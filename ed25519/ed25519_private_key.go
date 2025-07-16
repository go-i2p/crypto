package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// Ed25519PrivateKey represents an Ed25519 private key for digital signature operations.
// This key type implements the SigningPrivateKey interface and provides methods for
// signing data and generating verifiers. Ed25519 keys are 64 bytes in length.
type Ed25519PrivateKey ed25519.PrivateKey

// NewVerifier creates a verifier instance from this private key's public component.
// This method extracts the public key and returns a verifier that can validate signatures
// created by this private key. Returns an error if the private key size is invalid.
// NewVerifier implements types.SigningPublicKey.
func (k *Ed25519PrivateKey) NewVerifier() (types.Verifier, error) {
	// Validate private key size before proceeding with verifier creation
	if len(*k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519 private key size")
	}
	pub, err := k.Public()
	if err != nil {
		return nil, oops.Errorf("failed to get public key: %v", err)
	}
	return pub.NewVerifier()
}

// Bytes returns the raw byte representation of the Ed25519 private key.
// The returned slice contains the full 64-byte Ed25519 private key including
// the embedded public key portion. This method is used for serialization.
func (k Ed25519PrivateKey) Bytes() []byte {
	return k
}

// Zero securely clears the private key material from memory.
// This method overwrites all bytes of the private key with zeros to prevent
// potential memory disclosure attacks. Should be called when the key is no longer needed.
func (k Ed25519PrivateKey) Zero() {
	// Overwrite each byte to ensure secure memory cleanup
	for i := range k {
		k[i] = 0
	}
}

// NOTE: Ed25519 is a signature algorithm, not an encryption algorithm.
// This private key type does not implement types.DecryptingPrivateKey.
// For I2P decryption operations, use Curve25519 (X25519) instead.

// NewSigner creates a new signer instance for generating Ed25519 digital signatures.
// Returns a signer that can sign arbitrary data using this private key.
// The signer automatically handles hash computation before signing.
func (k Ed25519PrivateKey) NewSigner() (types.Signer, error) {
	// Verify key size meets Ed25519 requirements before creating signer
	if len(k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519 private key size")
	}
	return &Ed25519Signer{k: k}, nil
}

// Len returns the length of the Ed25519 private key in bytes.
// Ed25519 private keys are always 64 bytes long, containing both private
// and public key material as specified in RFC 8032.
func (k Ed25519PrivateKey) Len() int {
	return len(k)
}

// Generate creates a new random Ed25519 private key using secure random generation.
// This method generates a fresh keypair and returns it as a SigningPrivateKey interface.
// The generated key is cryptographically secure and suitable for production use.
func (k Ed25519PrivateKey) Generate() (types.SigningPrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate ed25519 key: %v", err)
	}
	// Copy the generated key to ensure proper memory management
	// Copy the full private key (includes public key)
	newKey := make(Ed25519PrivateKey, ed25519.PrivateKeySize)
	copy(newKey, priv)
	return newKey, nil
}

// Public extracts the Ed25519 public key from this private key.
// Returns the corresponding public key that can be used for signature verification.
// The public key is derived from the private key's embedded public component.
func (k Ed25519PrivateKey) Public() (types.SigningPublicKey, error) {
	log.WithField("key_length", len(k)).Debug("Ed25519PrivateKey.Public() called")
	// Validate private key size before extracting public key
	if len(k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519 private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(k))
	}
	// Extract the 32-byte public key portion from the 64-byte private key
	// Extract public key portion (last 32 bytes)
	pubKey := ed25519.PrivateKey(k).Public().(ed25519.PublicKey)
	log.WithField("pubkey_length", len(pubKey)).Debug("Ed25519PrivateKey.Public() extracted public key")
	return Ed25519PublicKey(pubKey), nil
}

// CreateEd25519PrivateKeyFromBytes constructs an Ed25519 private key from raw byte data.
// The input data must be exactly 64 bytes representing a valid Ed25519 private key.
// Returns an error if the data length is incorrect or the key format is invalid.
func CreateEd25519PrivateKeyFromBytes(data []byte) (Ed25519PrivateKey, error) {
	// Validate input byte length matches Ed25519 private key requirements
	if len(data) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519 private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(data))
	}
	// Create a defensive copy to prevent external mutation of key material
	privKey := make(Ed25519PrivateKey, ed25519.PrivateKeySize)
	copy(privKey, data)
	return privKey, nil
}
