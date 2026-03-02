package red25519

import (
	"crypto/rand"

	"github.com/go-i2p/crypto/types"
	upstream "github.com/go-i2p/red25519"
	"github.com/samber/oops"
)

// Red25519PrivateKey represents a Red25519 private key for signing and key blinding operations.
// The key format is identical to standard Ed25519 (64 bytes: 32-byte seed + 32-byte public key),
// but the signing and verification use Red25519's stricter validation (rejecting small-order keys).
//
// CRITICAL: Always use NewRed25519PrivateKey() or GenerateRed25519KeyPair() to create instances.
//
// Security:
//   - Private keys contain sensitive material
//   - Always call Zero() when done to clear memory
//   - Never log or transmit private keys
type Red25519PrivateKey upstream.PrivateKey

// NewVerifier creates a verifier instance from this private key's public component.
// This method extracts the public key and returns a Red25519 verifier that can
// validate signatures created by this private key.
func (k *Red25519PrivateKey) NewVerifier() (types.Verifier, error) {
	if len(*k) != PrivateKeySize {
		return nil, oops.Errorf("invalid red25519 private key size")
	}
	pub, err := k.Public()
	if err != nil {
		return nil, oops.Errorf("failed to get public key: %v", err)
	}
	return pub.NewVerifier()
}

// Bytes returns the raw byte representation of the Red25519 private key.
// The returned slice contains the full 64-byte private key including
// the seed and the embedded public key portion.
func (k Red25519PrivateKey) Bytes() []byte {
	return k
}

// Zero securely clears the private key material from memory.
// This method overwrites all bytes of the private key with zeros to prevent
// potential memory disclosure attacks. Should be called when the key is no longer needed.
func (k Red25519PrivateKey) Zero() {
	for i := range k {
		k[i] = 0
	}
}

// NewSigner creates a new Red25519 signer instance for generating signatures.
// Returns a signer that creates Red25519 signatures compatible with Ed25519.
func (k Red25519PrivateKey) NewSigner() (types.Signer, error) {
	if len(k) != PrivateKeySize {
		return nil, oops.Errorf("invalid red25519 private key size")
	}
	return &Red25519Signer{k: upstream.PrivateKey(k)}, nil
}

// Len returns the length of the Red25519 private key in bytes.
// Red25519 private keys are always 64 bytes long.
func (k Red25519PrivateKey) Len() int {
	return len(k)
}

// Generate creates a new random Red25519 private key.
// This method generates a fresh keypair and returns it as a SigningPrivateKey interface.
func (k Red25519PrivateKey) Generate() (types.SigningPrivateKey, error) {
	_, priv, err := upstream.GenerateKey(rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate red25519 key: %v", err)
	}
	newKey := make(Red25519PrivateKey, PrivateKeySize)
	copy(newKey, priv)
	return newKey, nil
}

// Public extracts the Red25519 public key from this private key.
// Returns the corresponding public key for Red25519 signature verification.
func (k Red25519PrivateKey) Public() (types.SigningPublicKey, error) {
	log.WithField("key_length", len(k)).Debug("Red25519PrivateKey.Public() called")
	if len(k) != PrivateKeySize {
		return nil, oops.Errorf("invalid red25519 private key size: expected %d, got %d",
			PrivateKeySize, len(k))
	}
	pubKey := upstream.PrivateKey(k).Public().(upstream.PublicKey)
	log.WithField("pubkey_length", len(pubKey)).Debug("Red25519PrivateKey.Public() extracted public key")
	return Red25519PublicKey(pubKey), nil
}

// NewRed25519PrivateKey creates a validated Red25519 private key from bytes.
// This is the REQUIRED constructor.
//
// Parameters:
//   - data: Must be exactly 64 bytes
//
// Returns error if data length is invalid.
func NewRed25519PrivateKey(data []byte) (Red25519PrivateKey, error) {
	if len(data) != PrivateKeySize {
		return nil, oops.Errorf("invalid red25519 private key size: expected %d, got %d",
			PrivateKeySize, len(data))
	}
	privKey := make(Red25519PrivateKey, PrivateKeySize)
	copy(privKey, data)
	return privKey, nil
}
