package ed25519ph

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestNewEd25519phPrivateKeyFromSeedRoundTrip proves the 32-byte seed form from
// common-structures.md §SigningPrivateKey ("EdDSA_SHA512_Ed25519ph … 32")
// expands to the key Go holds in memory and that Seed() returns the same bytes.
func TestNewEd25519phPrivateKeyFromSeedRoundTrip(t *testing.T) {
	_, std, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	seed := std.Seed()
	if SeedSize != 32 {
		t.Fatalf("SeedSize = %d, want 32", SeedSize)
	}

	k, err := NewEd25519phPrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewEd25519phPrivateKeyFromSeed: %v", err)
	}
	if len(k) != ed25519.PrivateKeySize {
		t.Errorf("expanded key is %d bytes, want %d", len(k), ed25519.PrivateKeySize)
	}
	if !bytes.Equal(k, std) {
		t.Error("seed expansion does not match the original key")
	}
	back, err := k.Seed()
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if !bytes.Equal(back, seed) {
		t.Error("Seed() did not return the original seed")
	}
}

// TestEd25519phSeedRejectsWrongSize guards against feeding the 64-byte expanded
// form to the seed constructor.
func TestEd25519phSeedRejectsWrongSize(t *testing.T) {
	if _, err := NewEd25519phPrivateKeyFromSeed(make([]byte, ed25519.PrivateKeySize)); err == nil {
		t.Error("accepted 64 bytes; the seed constructor takes 32")
	}
	if _, err := NewEd25519phPrivateKeyFromSeed(make([]byte, 33)); err == nil {
		t.Error("accepted 33-byte seed")
	}
	var short Ed25519phPrivateKey = make([]byte, 8)
	if _, err := short.Seed(); err == nil {
		t.Error("Seed() accepted a malformed key")
	}
}
