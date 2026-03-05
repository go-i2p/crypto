// Package siphash provides a thin wrapper around github.com/dchest/siphash,
// centralising third-party SipHash access within the go-i2p/crypto layer.
//
// SipHash is a fast, cryptographically strong pseudorandom function optimised
// for short inputs. In I2P it is used by NTCP2 for obfuscated frame-length
// encoding (SipHash-2-4 with a 128-bit key derived during the handshake).
//
// All callers in the go-i2p ecosystem SHOULD import this package instead of
// the upstream library directly, so that the implementation can be audited
// and swapped in a single location.
//
// Example usage:
//
//	key0, key1 := binary.LittleEndian.Uint64(k[0:8]), binary.LittleEndian.Uint64(k[8:16])
//	hash := siphash.Hash(key0, key1, data)
package siphash

import (
	"hash"

	upstream "github.com/dchest/siphash"
)

// Hash returns the SipHash-2-4 of the given message with two 64-bit key parts.
// This is the primary entry-point used by NTCP2 frame-length obfuscation.
//
// Parameters:
//   - k0: First 64-bit half of the 128-bit SipHash key
//   - k1: Second 64-bit half of the 128-bit SipHash key
//   - data: The message to hash
//
// Returns:
//   - uint64: The 64-bit SipHash-2-4 digest
func Hash(k0, k1 uint64, data []byte) uint64 {
	return upstream.Hash(k0, k1, data)
}

// New returns a new hash.Hash64 computing SipHash-2-4 with the given 128-bit key.
// The key slice must be exactly 16 bytes long.
//
// The returned hash.Hash64 implements streaming writes via Write() and final
// digest retrieval via Sum64(), which is useful when data is accumulated
// incrementally.
//
// Parameters:
//   - key: A 16-byte (128-bit) SipHash key
//
// Returns:
//   - hash.Hash64: A streaming SipHash-2-4 instance
func New(key []byte) hash.Hash64 {
	return upstream.New(key)
}

// New128 returns a new hash.Hash computing SipHash-2-4-128 with the given
// 128-bit key. The key slice must be exactly 16 bytes long.
//
// Parameters:
//   - key: A 16-byte (128-bit) SipHash key
//
// Returns:
//   - hash.Hash: A streaming SipHash-2-4-128 instance
func New128(key []byte) hash.Hash {
	return upstream.New128(key)
}

// Hash128 returns both 64-bit halves of a SipHash-2-4-128 digest.
// Some protocols require the full 128-bit output for stronger collision
// resistance or to derive two independent values from a single hash.
//
// Parameters:
//   - k0: First 64-bit half of the 128-bit SipHash key
//   - k1: Second 64-bit half of the 128-bit SipHash key
//   - data: The message to hash
//
// Returns:
//   - lo: Lower 64 bits of the 128-bit digest
//   - hi: Upper 64 bits of the 128-bit digest
func Hash128(k0, k1 uint64, data []byte) (lo, hi uint64) {
	return upstream.Hash128(k0, k1, data)
}
