package types

import (
	"crypto/sha256"
)

// KeyDeriver provides a standard interface for key derivation functions (KDFs)
type KeyDeriver interface {
	// Derive derives a key of the specified length from the input key material (IKM)
	Derive(ikm, salt, info []byte, keyLen int) ([]byte, error)
	// DeriveDefault derives a key using default parameters (32 bytes, no salt, no info)
	DeriveDefault(ikm []byte) ([]byte, error)
}

var SHA256 = sha256.Sum256
