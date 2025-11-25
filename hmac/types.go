package hmac

import (
	"crypto/rand"

	"github.com/samber/oops"
)

// HMACKey represents a 256-bit cryptographic key for HMAC-SHA256 authentication operations.
// This fixed-size array provides the symmetric key material required for generating and verifying
// HMAC signatures in I2P network communications. The 32-byte length ensures 256-bit security strength
// compatible with SHA-256 hash function requirements and I2P protocol specifications.
//
// ⚠️ CRITICAL SECURITY WARNING ⚠️
// Always use NewHMACKey() or GenerateHMACKey() to create instances.
// Direct construction creates zero-value keys which are cryptographically invalid.
//
// WRONG - Cryptographically invalid:
//
//	var key HMACKey  // All zeros - predictable and insecure!
//	key := HMACKey{} // Same issue
//
// CORRECT - Use constructors:
//
//	key, err := hmac.NewHMACKey(keyBytes)
//	if err != nil {
//	    return err
//	}
//	defer key.Zero()  // Clear sensitive material when done
//
// Or generate a new random key:
//
//	key, err := hmac.GenerateHMACKey()
//	if err != nil {
//	    return err
//	}
//	defer key.Zero()
//
// Keys should be generated using cryptographically secure random number generators to prevent
// authentication bypass attacks. Zero-value keys compromise the entire HMAC authentication scheme.
//
// Moved from: hmac.go
type HMACKey [32]byte

// HMACDigest represents a 256-bit HMAC-SHA256 authentication digest output.
// This fixed-size array contains the computed HMAC signature that authenticates data integrity
// and origin verification in I2P cryptographic protocols. The 32-byte length matches SHA-256
// output size and provides 256-bit authentication strength against forgery attacks.
// Digest values should be compared using constant-time operations to prevent timing attacks.
// Example usage: digest := I2PHMAC(data, key); if hmac.Equal(digest[:], expected[:]) { ... }
// Moved from: hmac.go
type HMACDigest [32]byte

// NewHMACKey creates a validated HMAC key from bytes.
// This is the REQUIRED constructor for creating HMAC keys from existing key material.
//
// Parameters:
//   - data: Must be exactly 32 bytes (256 bits) for HMAC-SHA256
//
// Returns error if data length is invalid or key is all zeros (cryptographically weak).
//
// Security considerations:
//   - Key material should come from cryptographically secure random sources
//   - Never use predictable values, hardcoded constants, or passwords directly
//   - Use key derivation functions (like HKDF) if deriving from passwords
//   - Call Zero() on the key when no longer needed to clear sensitive material
//
// Example usage:
//
//	keyBytes := make([]byte, 32)
//	if _, err := rand.Read(keyBytes); err != nil {
//	    return err
//	}
//	key, err := hmac.NewHMACKey(keyBytes)
//	if err != nil {
//	    return err
//	}
//	defer key.Zero()
func NewHMACKey(data []byte) (*HMACKey, error) {
	if len(data) != 32 {
		return nil, oops.Errorf("invalid HMAC key size: expected 32 bytes, got %d", len(data))
	}

	// Check for all-zero key (cryptographically weak)
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, oops.Errorf("HMAC key cannot be all zeros - this is cryptographically insecure")
	}

	// Create defensive copy to prevent external mutation
	var key HMACKey
	copy(key[:], data)

	return &key, nil
}

// GenerateHMACKey creates a new random HMAC key using cryptographically secure randomness.
// This is the recommended way to create new HMAC keys for authentication operations.
//
// The key is generated using crypto/rand, which provides cryptographically secure
// random bytes suitable for key material. Returns error if the system's random
// number generator fails.
//
// Security considerations:
//   - Always check the error return - random number generation can fail
//   - Call Zero() on the key when no longer needed to clear sensitive material
//   - Store keys securely (encrypted at rest, never in logs or version control)
//
// Example usage:
//
//	key, err := hmac.GenerateHMACKey()
//	if err != nil {
//	    return err
//	}
//	defer key.Zero()
//
//	// Use key for HMAC operations
//	digest := I2PHMAC(data, *key)
func GenerateHMACKey() (*HMACKey, error) {
	var key HMACKey
	if _, err := rand.Read(key[:]); err != nil {
		return nil, oops.Wrapf(err, "failed to generate random HMAC key")
	}
	return &key, nil
}

// Zero securely clears the HMAC key material from memory.
// This method should be called when the key is no longer needed to prevent
// sensitive material from remaining in memory where it could be disclosed
// through memory dumps, swap files, or other memory access vectors.
//
// Best practice: Use defer to ensure keys are always zeroed:
//
//	key, err := hmac.GenerateHMACKey()
//	if err != nil {
//	    return err
//	}
//	defer key.Zero()
//
// Note: While Go's garbage collector will eventually reclaim the memory,
// it does not guarantee that the memory contents will be overwritten.
// Explicit zeroing provides defense-in-depth against memory disclosure attacks.
func (k *HMACKey) Zero() {
	for i := range k {
		k[i] = 0
	}
}
