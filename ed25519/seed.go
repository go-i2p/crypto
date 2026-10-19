package ed25519

import (
	"crypto/ed25519"

	"github.com/samber/oops"
)

// SeedSize is the length in bytes of an Ed25519 private key seed, which is the
// form the I2P specification uses for a SigningPrivateKey.
//
// common-structures.md §SigningPrivateKey lists, for the EdDSA and RedDSA types:
//
//	EdDSA_SHA512_Ed25519   | 32 | 0.9.15
//	EdDSA_SHA512_Ed25519ph | 32 | 0.9.25
//	RedDSA_SHA512_Ed25519  | 32 | 0.9.39
//
// and §Notes adds: "All types are Big Endian, except for EdDSA and RedDSA, which
// are stored and transmitted in a Little Endian format."
//
// The 32-byte value is the seed; Go's crypto/ed25519 represents a private key as
// the 64-byte expansion seed‖publicKey. That 64-byte layout is an in-memory
// detail of the Go standard library, not the wire/file format. Use [Seed] to get
// the 32-byte form for serialization and
// [NewEd25519PrivateKeyFromSeed] to build a key from it.
const SeedSize = ed25519.SeedSize

// Seed returns the 32-byte seed of the private key, which is the form
// common-structures.md §SigningPrivateKey specifies for EdDSA_SHA512_Ed25519.
// This is what a Java router writes to router.config / i2pdirector.xml and what
// I2CP transmits; [Ed25519PrivateKey.Bytes] returns Go's 64-byte expanded form
// instead.
//
// Returns an error if the key is not the valid 64-byte expanded length.
func (k Ed25519PrivateKey) Seed() ([]byte, error) {
	if len(k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519 private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(k))
	}
	seed := make([]byte, SeedSize)
	copy(seed, k[:SeedSize])
	return seed, nil
}

// NewEd25519PrivateKeyFromSeed creates an Ed25519 private key from its 32-byte
// seed — the canonical I2P SigningPrivateKey encoding per common-structures.md
// §SigningPrivateKey ("EdDSA_SHA512_Ed25519 … 32"). This is the constructor to
// use when importing a key produced by a Java router (router.config,
// i2pdirector.xml, an I2CP SigningPrivateKey, or a Destination handoff), all of
// which carry the 32-byte seed, not Go's 64-byte expansion.
//
// The seed is expanded with ed25519.NewKeyFromSeed, which derives the public key
// and yields the 64-byte in-memory form the rest of this type expects.
//
// Parameters:
//   - seed: exactly 32 bytes
//
// Returns error if seed is not 32 bytes.
func NewEd25519PrivateKeyFromSeed(seed []byte) (Ed25519PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, oops.Errorf("invalid ed25519 seed size: expected %d, got %d", SeedSize, len(seed))
	}
	full := ed25519.NewKeyFromSeed(seed)
	privKey := make(Ed25519PrivateKey, ed25519.PrivateKeySize)
	copy(privKey, full)
	return privKey, nil
}
