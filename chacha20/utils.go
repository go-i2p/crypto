package chacha20

import (
	"github.com/go-i2p/crypto/rand"
	"github.com/samber/oops"
)

// NewRandomNonce generates a cryptographically secure random nonce for ChaCha20.
// Returns a 96-bit nonce suitable for ChaCha20-Poly1305 AEAD encryption.
// Moved from: chacha20.go
func NewRandomNonce() (ChaCha20Nonce, error) {
	var nonce ChaCha20Nonce
	_, err := rand.Read(nonce[:])
	if err != nil {
		return ChaCha20Nonce{}, oops.Errorf("failed to generate random nonce: %w", err)
	}
	return nonce, nil
}
