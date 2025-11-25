package chacha20

import (
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// NewChaCha20Key creates a validated ChaCha20 key from bytes.
//
// This constructor provides mandatory validation to prevent common security issues:
//   - Rejects keys that are not exactly 32 bytes (ChaCha20 standard)
//   - Warns if key is all zeros (cryptographically weak but technically valid)
//   - Returns defensive copy to prevent external mutation
//
// Parameters:
//   - data: Must be exactly 32 bytes (KeySize)
//
// Returns an error if:
//   - Key size is not 32 bytes
//   - Key is nil
//
// Example usage:
//
//	key, err := chacha20.NewChaCha20Key(keyBytes)
//	if err != nil {
//	    return err
//	}
//	defer key.Zero()
func NewChaCha20Key(data []byte) (*ChaCha20Key, error) {
	if len(data) != KeySize {
		return nil, oops.Errorf("invalid ChaCha20 key size: expected %d bytes, got %d bytes", KeySize, len(data))
	}

	// Check for all-zero key (weak but technically valid)
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		log.Warn("ChaCha20 key is all zeros - this is cryptographically weak")
	}

	// Create defensive copy
	var key ChaCha20Key
	copy(key[:], data)
	return &key, nil
}

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

// Zero securely clears the ChaCha20 key from memory.
// This method should be called when the key is no longer needed to prevent
// memory disclosure attacks. After calling Zero, the key becomes unusable.
func (k *ChaCha20Key) Zero() {
	for i := range k {
		k[i] = 0
	}
}
