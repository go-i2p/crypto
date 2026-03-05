package curve25519

import (
	"crypto/rand"
	"testing"

	"go.step.sm/crypto/x25519"
)

func TestSharedKey(t *testing.T) {
	// Generate two key pairs
	pubA, privA, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	pubB, privB, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}

	// A computes shared secret with B's public key
	sharedAB, err := SharedKey(privA, pubB[:])
	if err != nil {
		t.Fatalf("SharedKey(A, pubB): %v", err)
	}

	// B computes shared secret with A's public key
	sharedBA, err := SharedKey(privB, pubA[:])
	if err != nil {
		t.Fatalf("SharedKey(B, pubA): %v", err)
	}

	// Both shared secrets must be identical (DH symmetry)
	if len(sharedAB) != 32 {
		t.Fatalf("shared secret length = %d, want 32", len(sharedAB))
	}
	for i := range sharedAB {
		if sharedAB[i] != sharedBA[i] {
			t.Fatalf("shared secrets differ at byte %d", i)
		}
	}
}

func TestSharedKeyMatchesX25519(t *testing.T) {
	// Verify our SharedKey produces the same result as x25519 directly
	pubA, privA, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, privB, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Compute via x25519 library directly
	expected, err := x25519.PrivateKey(privB).SharedKey(pubA)
	if err != nil {
		t.Fatalf("x25519 SharedKey: %v", err)
	}

	// Compute via our wrapper
	got, err := SharedKey(privB, pubA[:])
	if err != nil {
		t.Fatalf("SharedKey: %v", err)
	}

	for i := range expected {
		if expected[i] != got[i] {
			t.Fatalf("mismatch at byte %d: expected %02x, got %02x", i, expected[i], got[i])
		}
	}

	// Also test with typed keys
	typedPriv, err := NewCurve25519PrivateKey(privA)
	if err != nil {
		t.Fatalf("NewCurve25519PrivateKey: %v", err)
	}
	typedPub, err := NewCurve25519PublicKey(pubA[:])
	if err != nil {
		t.Fatalf("NewCurve25519PublicKey: %v", err)
	}
	_ = typedPriv
	_ = typedPub
}

func TestSharedKeyInvalidInputs(t *testing.T) {
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i + 1)
	}

	t.Run("nil private key", func(t *testing.T) {
		_, err := SharedKey(nil, validKey)
		if err == nil {
			t.Error("expected error for nil private key")
		}
	})

	t.Run("short private key", func(t *testing.T) {
		_, err := SharedKey(make([]byte, 16), validKey)
		if err == nil {
			t.Error("expected error for short private key")
		}
	})

	t.Run("long private key", func(t *testing.T) {
		_, err := SharedKey(make([]byte, 64), validKey)
		if err == nil {
			t.Error("expected error for long private key")
		}
	})

	t.Run("nil public key", func(t *testing.T) {
		_, err := SharedKey(validKey, nil)
		if err == nil {
			t.Error("expected error for nil public key")
		}
	})

	t.Run("short public key", func(t *testing.T) {
		_, err := SharedKey(validKey, make([]byte, 16))
		if err == nil {
			t.Error("expected error for short public key")
		}
	})

	t.Run("long public key", func(t *testing.T) {
		_, err := SharedKey(validKey, make([]byte, 64))
		if err == nil {
			t.Error("expected error for long public key")
		}
	})
}

func TestSharedKeyFromTyped(t *testing.T) {
	pubA, privA, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	pubB, privB, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}

	typedPrivA, err := NewCurve25519PrivateKey(privA)
	if err != nil {
		t.Fatalf("NewCurve25519PrivateKey A: %v", err)
	}
	typedPubB, err := NewCurve25519PublicKey(pubB[:])
	if err != nil {
		t.Fatalf("NewCurve25519PublicKey B: %v", err)
	}

	typedPrivB, err := NewCurve25519PrivateKey(privB)
	if err != nil {
		t.Fatalf("NewCurve25519PrivateKey B: %v", err)
	}
	typedPubA, err := NewCurve25519PublicKey(pubA[:])
	if err != nil {
		t.Fatalf("NewCurve25519PublicKey A: %v", err)
	}

	sharedAB, err := SharedKeyFromTyped(typedPrivA, typedPubB)
	if err != nil {
		t.Fatalf("SharedKeyFromTyped(A, B): %v", err)
	}

	sharedBA, err := SharedKeyFromTyped(typedPrivB, typedPubA)
	if err != nil {
		t.Fatalf("SharedKeyFromTyped(B, A): %v", err)
	}

	for i := range sharedAB {
		if sharedAB[i] != sharedBA[i] {
			t.Fatalf("typed shared secrets differ at byte %d", i)
		}
	}

	// nil inputs
	_, err = SharedKeyFromTyped(nil, typedPubB)
	if err == nil {
		t.Error("expected error for nil private key")
	}
	_, err = SharedKeyFromTyped(typedPrivA, nil)
	if err == nil {
		t.Error("expected error for nil public key")
	}
}
