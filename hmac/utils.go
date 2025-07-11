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
	return
}
