package ed25519ph

import (
	"crypto/ed25519"

	"github.com/samber/oops"
)

// SeedSize is the length in bytes of an Ed25519ph private key seed, the form the
// I2P specification uses for a SigningPrivateKey.
//
// common-structures.md §SigningPrivateKey lists "EdDSA_SHA512_Ed25519ph | 32 |
// 0.9.25 | Offline signing, never used for Router Identities or Destinations",
// and §Notes adds: "All types are Big Endian, except for EdDSA and RedDSA, which
// are stored and transmitted in a Little Endian format."
//
// The 32 bytes is the seed. Go's crypto/ed25519 keeps a private key as the
// 64-byte expansion seed‖publicKey, and [Ed25519phPrivateKey] follows that
// in-memory layout. Use [Seed] to export and
// [NewEd25519phPrivateKeyFromSeed] to import the 32-byte spec form.
const SeedSize = ed25519.SeedSize

// Seed returns the 32-byte seed of the private key, the form
// common-structures.md §SigningPrivateKey specifies for
// EdDSA_SHA512_Ed25519ph. Returns an error if the key is not the valid 64-byte
// expanded length.
func (k Ed25519phPrivateKey) Seed() ([]byte, error) {
	if len(k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519ph private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(k))
	}
	seed := make([]byte, SeedSize)
	copy(seed, k[:SeedSize])
	return seed, nil
}

// NewEd25519phPrivateKeyFromSeed creates an Ed25519ph private key from its
// 32-byte seed - the canonical I2P SigningPrivateKey encoding per
// common-structures.md §SigningPrivateKey ("EdDSA_SHA512_Ed25519ph … 32").
// Ed25519ph is used for offline signing, so this is the constructor for loading a
// key from a Java-produced offline-signing file or an I2CP SigningPrivateKey.
//
// Parameters:
//   - seed: exactly 32 bytes
//
// Returns error if seed is not 32 bytes.
func NewEd25519phPrivateKeyFromSeed(seed []byte) (Ed25519phPrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, oops.Errorf("invalid ed25519ph seed size: expected %d, got %d", SeedSize, len(seed))
	}
	full := ed25519.NewKeyFromSeed(seed)
	privKey := make(Ed25519phPrivateKey, ed25519.PrivateKeySize)
	copy(privKey, full)
	return privKey, nil
}
