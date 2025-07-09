package chacha20

import (
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// GenerateKey creates a new random ChaCha20 key
func GenerateKey() (*ChaCha20Key, error) {
	key := new(ChaCha20Key)
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, oops.Errorf("failed to generate ChaCha20 key: %w", err)
	}
	return key, nil
}

// Len returns the length of the key in bytes
func (k *ChaCha20Key) Len() int {
	return KeySize
}

// Bytes returns the key as a byte slice
func (k *ChaCha20Key) Bytes() []byte {
	return k[:]
}

// NewEncrypter creates a new encrypter using this key
func (k *ChaCha20Key) NewEncrypter() (types.Encrypter, error) {
	return &ChaCha20PolyEncrypter{Key: *k}, nil
}

// NewDecrypter creates a new decrypter using this key
func (k *ChaCha20Key) NewDecrypter() (types.Decrypter, error) {
	return &ChaCha20PolyDecrypter{Key: *k}, nil
}
