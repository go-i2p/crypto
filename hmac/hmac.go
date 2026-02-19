package hmac

import (
	"crypto/hmac"
	"hash"
)

// New returns a new HMAC hash using the given hash function and key.
// This is a drop-in replacement for crypto/hmac.New, allowing callers to use
// github.com/go-i2p/crypto/hmac as a substitute for the standard library package.
//
// The returned hash.Hash supports streaming writes via Write() and final
// digest retrieval via Sum(nil), which is required for multi-step HMAC chains
// such as the NTCP2 KDF.
//
// Example usage:
//
//	mac := hmac.New(sha256.New, key)
//	mac.Write(data)
//	digest := mac.Sum(nil)
func New(h func() hash.Hash, key []byte) hash.Hash {
	return hmac.New(h, key)
}

// Equal compares two MACs for equality without leaking timing information.
// This is a drop-in replacement for crypto/hmac.Equal.
//
// It should be used whenever comparing HMAC digests to prevent timing
// side-channel attacks that could allow an attacker to forge valid MACs.
//
// Example usage:
//
//	expected := computeMAC(message, key)
//	if !hmac.Equal(expected, received) {
//	    return errors.New("authentication failed")
//	}
func Equal(mac1, mac2 []byte) bool {
	return hmac.Equal(mac1, mac2)
}
