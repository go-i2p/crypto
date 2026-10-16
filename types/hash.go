package types

import (
	"crypto/sha256"
)

// KeyDeriver interface provides a standard contract for key derivation functions (KDFs).
// Key derivation functions are cryptographic algorithms that derive one or more secret keys
// from a secret value such as a master key, password, or passphrase using a pseudorandom function.
// This interface enables consistent key derivation across different cryptographic implementations.
type KeyDeriver interface {
	// Derive derives a key of the specified length from the input key material (IKM).
	// Parameters:
	// - ikm: Input key material, the source entropy for key derivation
	// - salt: Optional salt value to ensure different outputs for the same IKM
	// - info: Optional context and application-specific information. Not all
	//   implementations support it; for example Argon2id ignores this parameter
	//   because the Go standard library does not expose the Argon2 secret/context
	//   input.
	// - keyLen: Desired length of the derived key in bytes
	// Returns the derived key bytes or an error if derivation fails.
	Derive(ikm, salt, info []byte, keyLen int) ([]byte, error)

	// DeriveDefault derives a key using default parameters for common use
	// cases. This method uses a 32-byte output and no info context.
	//
	// Implementations that require a salt (for example Argon2id) cannot honor a
	// "no salt" default and will return an error; check the concrete type's
	// documentation.
	DeriveDefault(ikm []byte) ([]byte, error)
}

// SHA256 provides a convenient alias for the standard SHA-256 hash function.
// This variable allows direct access to SHA-256 hashing without importing crypto/sha256
// in packages that primarily use other cryptographic operations.
var SHA256 = sha256.Sum256
