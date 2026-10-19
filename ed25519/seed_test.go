package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestNewEd25519PrivateKeyFromSeedRoundTrip proves the 32-byte seed form the I2P
// spec uses (common-structures.md §SigningPrivateKey: EdDSA = 32 bytes) expands
// to the same key Go holds in memory, and that Seed() returns exactly the bytes
// a Java router would have written.
func TestNewEd25519PrivateKeyFromSeedRoundTrip(t *testing.T) {
	_, std, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	seed := std.Seed()
	if len(seed) != SeedSize || SeedSize != 32 {
		t.Fatalf("SeedSize = %d, want 32", SeedSize)
	}

	k, err := NewEd25519PrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewEd25519PrivateKeyFromSeed: %v", err)
	}
	if len(k) != ed25519.PrivateKeySize {
		t.Errorf("expanded key is %d bytes, want %d", len(k), ed25519.PrivateKeySize)
	}
	if !bytes.Equal(k, std) {
		t.Error("seed expansion does not match the original key")
	}

	// Seed() must hand back the 32-byte canonical form.
	back, err := k.Seed()
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if !bytes.Equal(back, seed) {
		t.Error("Seed() did not return the original 32-byte seed")
	}

	// The derived public key must match too - this is what actually matters for
	// a Destination/RouterIdentity handoff.
	pub, err := k.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	if !bytes.Equal(pub.Bytes(), std.Public().(ed25519.PublicKey)) {
		t.Error("public key derived from seed-expanded key differs")
	}
}

// TestSeedRejectsWrongSize guards the constructor against the 64-byte form and
// other lengths: a caller pasting Bytes() output into the seed constructor must
// get a clear error rather than a silently wrong key.
func TestSeedRejectsWrongSize(t *testing.T) {
	full := make([]byte, ed25519.PrivateKeySize)
	if _, err := NewEd25519PrivateKeyFromSeed(full); err == nil {
		t.Error("NewEd25519PrivateKeyFromSeed accepted 64 bytes; it takes a 32-byte seed")
	}
	if _, err := NewEd25519PrivateKeyFromSeed(make([]byte, 31)); err == nil {
		t.Error("accepted 31-byte seed")
	}
	// Seed() on a malformed key must error, not panic.
	var short Ed25519PrivateKey = make([]byte, 10)
	if _, err := short.Seed(); err == nil {
		t.Error("Seed() accepted a malformed key")
	}
}

// TestSeedFormIsLittleEndianSeedOnly documents the interoperability property: the
// I2P SigningPrivateKey for EdDSA is the raw 32-byte seed (RFC 8032 encoding),
// which is little-endian by construction, whereas Bytes() emits the 64-byte
// expanded form. A Java key import must go through the seed constructor.
func TestSeedFormMatchesJavaLength(t *testing.T) {
	_, std, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	k, err := NewEd25519PrivateKey(std)
	if err != nil {
		t.Fatalf("NewEd25519PrivateKey: %v", err)
	}
	seed, err := k.Seed()
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if len(seed) != 32 {
		t.Errorf("seed is %d bytes; common-structures.md §SigningPrivateKey says EdDSA_SHA512_Ed25519 is 32", len(seed))
	}
	if len(k.Bytes()) != 64 {
		t.Errorf("Bytes() is %d bytes, want 64 (Go's expanded in-memory form)", len(k.Bytes()))
	}

	// Signing with the seed-expanded key must verify against the original.
	sig, err := k.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	msg := []byte("destination handoff")
	s, err := sig.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(std.Public().(ed25519.PublicKey), msg, s) {
		t.Error("signature from seed-expanded key failed to verify against the original public key")
	}
}
