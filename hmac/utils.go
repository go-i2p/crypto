package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
)

// I2PHMAC computes HMAC-SHA256 using the provided key and data.
// This function implements the I2P standard HMAC computation using SHA256.
// Moved from: hmac.go
func I2PHMAC(data []byte, k HMACKey) (d HMACDigest) {
	// Create a new HMAC instance using SHA256 hash and our key
	mac := hmac.New(sha256.New, k[:])

	// Write data to HMAC
	mac.Write(data)

	// Calculate the HMAC and extract the digest
	digest := mac.Sum(nil)

	// Copy to our fixed-size return type
	copy(d[:], digest)
	return d
}

// HMACSHA256 computes HMAC-SHA256 over data using the provided key and returns
// the 32-byte digest as a fixed-size array. Unlike I2PHMAC, this function
// accepts arbitrary-length key and data slices, making it suitable as a
// general-purpose HMAC-SHA256 primitive for use across I2P components such as
// noise handshakes and NTCP2 KDF chains.
//
// Parameters:
//   - key: HMAC key of arbitrary length (will be hashed internally if >64 bytes)
//   - data: The message data to authenticate
//
// Returns:
//   - [32]byte: The 32-byte HMAC-SHA256 digest
//
// Example usage:
//
//	mac := hmac.HMACSHA256(chainKey[:], inputKeyMaterial)
//	// mac is a [32]byte ready for further KDF chaining
func HMACSHA256(key, data []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}
