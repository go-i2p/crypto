package hmac

// HMACKey represents a 256-bit cryptographic key for HMAC-SHA256 authentication operations.
// This fixed-size array provides the symmetric key material required for generating and verifying
// HMAC signatures in I2P network communications. The 32-byte length ensures 256-bit security strength
// compatible with SHA-256 hash function requirements and I2P protocol specifications.
// Keys should be generated using cryptographically secure random number generators to prevent
// authentication bypass attacks. Example usage: var key HMACKey; rand.Read(key[:])
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
