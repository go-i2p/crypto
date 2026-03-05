package curve25519

import (
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

// SharedKey computes a Curve25519 Diffie-Hellman shared secret.
// privateKey is 32 bytes (scalar), peerPublicKey is 32 bytes (point).
// Returns the 32-byte shared secret or an error if inputs are invalid.
//
// This is a convenience wrapper around x25519.PrivateKey.SharedKey and is
// intended as a drop-in replacement for go.step.sm/crypto/x25519 SharedKey
// usage in go-noise and similar callers:
//
//	sharedKey, err := curve25519.SharedKey(localPrivate, remotePublic)
func SharedKey(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != x25519.PrivateKeySize {
		return nil, oops.Errorf("curve25519 SharedKey: %w", ErrInvalidPrivateKey)
	}
	if len(peerPublicKey) != x25519.PublicKeySize {
		return nil, oops.Errorf("curve25519 SharedKey: %w", ErrInvalidPublicKey)
	}

	priv := make(x25519.PrivateKey, x25519.PrivateKeySize)
	copy(priv, privateKey)

	pub := make(x25519.PublicKey, x25519.PublicKeySize)
	copy(pub, peerPublicKey)

	shared, err := priv.SharedKey(pub)
	if err != nil {
		return nil, oops.Errorf("curve25519 SharedKey: %w", err)
	}
	return shared, nil
}

// SharedKeyFromTyped computes a Curve25519 Diffie-Hellman shared secret using
// the package's typed key representations.
func SharedKeyFromTyped(privateKey *Curve25519PrivateKey, peerPublicKey *Curve25519PublicKey) ([]byte, error) {
	if privateKey == nil {
		return nil, oops.Errorf("curve25519 SharedKey: %w", ErrInvalidPrivateKey)
	}
	if peerPublicKey == nil {
		return nil, oops.Errorf("curve25519 SharedKey: %w", ErrInvalidPublicKey)
	}
	return SharedKey(privateKey.Bytes(), peerPublicKey.Bytes())
}
