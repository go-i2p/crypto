package hmac

// HMACKey represents a 256-bit key for HMAC-SHA256 operations.
// Moved from: hmac.go
type HMACKey [32]byte

// HMACDigest represents a 256-bit HMAC-SHA256 digest output.
// Moved from: hmac.go
type HMACDigest [32]byte
