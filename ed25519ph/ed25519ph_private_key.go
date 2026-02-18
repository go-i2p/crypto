package ed25519ph

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// Ed25519phPrivateKey represents an Ed25519 private key for Ed25519ph signature operations.
// The key format is identical to standard Ed25519 (64 bytes), but the signing
// algorithm uses pre-hashing with SHA-512 and domain separation per RFC 8032 §5.1.
//
// CRITICAL: Always use NewEd25519phPrivateKey() to create instances.
//
// Security:
//   - Private keys contain sensitive material
//   - Always call Zero() when done to clear memory
//   - Never log or transmit private keys
type Ed25519phPrivateKey ed25519.PrivateKey

// NewVerifier creates a verifier instance from this private key's public component.
// This method extracts the public key and returns an Ed25519ph verifier that can
// validate signatures created by this private key.
func (k *Ed25519phPrivateKey) NewVerifier() (types.Verifier, error) {
	if len(*k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519ph private key size")
	}
	pub, err := k.Public()
	if err != nil {
		return nil, oops.Errorf("failed to get public key: %v", err)
	}
	return pub.NewVerifier()
}

// Bytes returns the raw byte representation of the Ed25519ph private key.
// The returned slice contains the full 64-byte Ed25519 private key including
// the embedded public key portion.
func (k Ed25519phPrivateKey) Bytes() []byte {
	return k
}

// Zero securely clears the private key material from memory.
// This method overwrites all bytes of the private key with zeros to prevent
// potential memory disclosure attacks. Should be called when the key is no longer needed.
func (k Ed25519phPrivateKey) Zero() {
	for i := range k {
		k[i] = 0
	}
}

// NewSigner creates a new Ed25519ph signer instance for generating pre-hashed signatures.
// Returns a signer that creates Ed25519ph signatures with domain separation per RFC 8032.
func (k Ed25519phPrivateKey) NewSigner() (types.Signer, error) {
	if len(k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519ph private key size")
	}
	return &Ed25519phSigner{k: k}, nil
}

// Len returns the length of the Ed25519ph private key in bytes.
// Ed25519 private keys are always 64 bytes long.
func (k Ed25519phPrivateKey) Len() int {
	return len(k)
}

// Generate creates a new random Ed25519 private key for use with Ed25519ph.
// This method generates a fresh keypair and returns it as a SigningPrivateKey interface.
func (k Ed25519phPrivateKey) Generate() (types.SigningPrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate ed25519ph key: %v", err)
	}
	newKey := make(Ed25519phPrivateKey, ed25519.PrivateKeySize)
	copy(newKey, priv)
	return newKey, nil
}

// Public extracts the Ed25519 public key from this private key.
// Returns the corresponding public key for Ed25519ph signature verification.
func (k Ed25519phPrivateKey) Public() (types.SigningPublicKey, error) {
	log.WithField("key_length", len(k)).Debug("Ed25519phPrivateKey.Public() called")
	if len(k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519ph private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(k))
	}
	pubKey := ed25519.PrivateKey(k).Public().(ed25519.PublicKey)
	log.WithField("pubkey_length", len(pubKey)).Debug("Ed25519phPrivateKey.Public() extracted public key")
	return Ed25519phPublicKey(pubKey), nil
}

// NewEd25519phPrivateKey creates a validated Ed25519ph private key from bytes.
// This is the REQUIRED constructor.
//
// Parameters:
//   - data: Must be exactly 64 bytes
//
// Returns error if data length is invalid.
func NewEd25519phPrivateKey(data []byte) (Ed25519phPrivateKey, error) {
	if len(data) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519ph private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(data))
	}
	privKey := make(Ed25519phPrivateKey, ed25519.PrivateKeySize)
	copy(privKey, data)
	return privKey, nil
}
