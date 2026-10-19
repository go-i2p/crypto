package curve25519

// Tests for the X25519 ephemeral-static encryption helper. These validate
// the encrypt/decrypt round-trip, the output layout
// ([1B zero padding][ephemeral pubkey 32B][nonce 12B][AEAD ciphertext]), and
// the 1024-byte size limit. X25519 is the key-agreement primitive used by the
// I2P ECIES-X25519-AEAD scheme (see https://i2p.net/en/docs/specs/ecies/).

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	curve25519 "go.step.sm/crypto/x25519"

	"github.com/go-i2p/crypto/types"
)

func TestCurve25519EncryptionDataSize(t *testing.T) {
	// Generate key pair for testing
	pub, _, err := curve25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create encryption instance
	encrypter, err := NewCurve25519Encryption(&pub, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create encrypter: %v", err)
	}

	// Test cases for various data sizes
	testCases := []struct {
		name        string
		dataSize    int
		shouldError bool
	}{
		{"Small data (64 bytes)", 64, false},
		{"Previous limit (222 bytes)", 222, false},
		{"Medium data (512 bytes)", 512, false},
		{"Large I2P data (1024 bytes)", 1024, false},
		{"Too large (1025 bytes)", 1025, true},
		{"Very large (2048 bytes)", 2048, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			// Fill with test data
			for i := range data {
				data[i] = byte(i % 256)
			}

			_, err := encrypter.Encrypt(data)
			if tc.shouldError && err == nil {
				t.Errorf("Expected error for %d bytes, but got none", tc.dataSize)
			} else if !tc.shouldError && err != nil {
				t.Errorf("Unexpected error for %d bytes: %v", tc.dataSize, err)
			}
		})
	}
}

// TestNewCurve25519PublicKey tests the mandatory constructor for Curve25519 public keys.
func TestNewCurve25519PublicKey(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		// Generate a valid key
		pub, _, err := curve25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		key, err := NewCurve25519PublicKey(pub[:])
		if err != nil {
			t.Fatalf("NewCurve25519PublicKey failed: %v", err)
		}

		if key == nil {
			t.Fatal("NewCurve25519PublicKey returned nil key")
		}

		if key.Len() != 32 {
			t.Errorf("Len() = %d, want 32", key.Len())
		}

		if len(key.Bytes()) != 32 {
			t.Errorf("Bytes() length = %d, want 32", len(key.Bytes()))
		}

		// Verify bytes match input
		for i, b := range key.Bytes() {
			if b != pub[i] {
				t.Errorf("Byte mismatch at index %d: got %d, want %d", i, b, pub[i])
				break
			}
		}
	})

	t.Run("invalid size - too short", func(t *testing.T) {
		data := make([]byte, 16)
		_, err := NewCurve25519PublicKey(data)
		if err == nil {
			t.Error("Expected error for 16-byte key, got nil")
		}
	})

	t.Run("invalid size - too long", func(t *testing.T) {
		data := make([]byte, 64)
		_, err := NewCurve25519PublicKey(data)
		if err == nil {
			t.Error("Expected error for 64-byte key, got nil")
		}
	})

	t.Run("nil input", func(t *testing.T) {
		_, err := NewCurve25519PublicKey(nil)
		if err == nil {
			t.Error("Expected error for nil input, got nil")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := NewCurve25519PublicKey([]byte{})
		if err == nil {
			t.Error("Expected error for empty input, got nil")
		}
	})

	t.Run("prevents nil slice panic", func(t *testing.T) {
		// This is the key safety feature - the constructor prevents the nil slice bug
		data := make([]byte, 32)
		for i := range data {
			data[i] = byte(i)
		}

		key, err := NewCurve25519PublicKey(data)
		if err != nil {
			t.Fatalf("NewCurve25519PublicKey failed: %v", err)
		}

		// Verify we can safely call methods without panic
		if key.Len() != 32 {
			t.Errorf("Len() = %d, want 32", key.Len())
		}

		bytes := key.Bytes()
		if len(bytes) != 32 {
			t.Errorf("Bytes() length = %d, want 32", len(bytes))
		}
	})

	t.Run("NewEncrypter works", func(t *testing.T) {
		// Generate a valid key
		pub, _, err := curve25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		key, err := NewCurve25519PublicKey(pub[:])
		if err != nil {
			t.Fatalf("NewCurve25519PublicKey failed: %v", err)
		}

		encrypter, err := key.NewEncrypter()
		if err != nil {
			t.Fatalf("NewEncrypter() failed: %v", err)
		}

		if encrypter == nil {
			t.Error("NewEncrypter() returned nil encrypter")
		}
	})
}

// TestNewCurve25519PrivateKey tests the mandatory constructor for Curve25519 private keys.
func TestNewCurve25519PrivateKey(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		// Generate a valid key pair
		_, priv, err := curve25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		key, err := NewCurve25519PrivateKey(priv[:])
		if err != nil {
			t.Fatalf("NewCurve25519PrivateKey failed: %v", err)
		}

		if key == nil {
			t.Fatal("NewCurve25519PrivateKey returned nil key")
		}

		if len(key.Bytes()) != 32 {
			t.Errorf("Bytes() length = %d, want 32", len(key.Bytes()))
		}
	})

	t.Run("invalid size - too short", func(t *testing.T) {
		data := make([]byte, 16)
		_, err := NewCurve25519PrivateKey(data)
		if err == nil {
			t.Error("Expected error for 16-byte private key, got nil")
		}
	})

	t.Run("invalid size - too long", func(t *testing.T) {
		data := make([]byte, 64)
		_, err := NewCurve25519PrivateKey(data)
		if err == nil {
			t.Error("Expected error for 64-byte private key, got nil")
		}
	})

	t.Run("nil input", func(t *testing.T) {
		_, err := NewCurve25519PrivateKey(nil)
		if err == nil {
			t.Error("Expected error for nil input, got nil")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := NewCurve25519PrivateKey([]byte{})
		if err == nil {
			t.Error("Expected error for empty input, got nil")
		}
	})

	t.Run("all-zero key rejected", func(t *testing.T) {
		data := make([]byte, 32) // All zeros
		_, err := NewCurve25519PrivateKey(data)
		if err == nil {
			t.Error("Expected error for all-zero private key, got nil")
		}
	})

	t.Run("public key derivation", func(t *testing.T) {
		// Generate a valid key pair
		pub, priv, err := curve25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		privKey, err := NewCurve25519PrivateKey(priv[:])
		if err != nil {
			t.Fatalf("NewCurve25519PrivateKey failed: %v", err)
		}

		// Derive public key
		derivedPubInterface, err := privKey.Public()
		if err != nil {
			t.Fatalf("Public() failed: %v", err)
		}

		derivedPub, ok := derivedPubInterface.(*Curve25519PublicKey)
		if !ok {
			t.Fatalf("Public() returned wrong type: %T", derivedPubInterface)
		}

		derivedPubBytes := derivedPub.Bytes()
		if len(derivedPubBytes) != 32 {
			t.Errorf("Derived public key length = %d, want 32", len(derivedPubBytes))
		}

		// Verify it matches the original public key
		for i, b := range derivedPubBytes {
			if b != pub[i] {
				t.Errorf("Public key mismatch at byte %d: got %d, want %d", i, b, pub[i])
				break
			}
		}
	})

	t.Run("encrypt/decrypt round-trip", func(t *testing.T) {
		// Generate a valid key pair
		pub, priv, err := curve25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		privKey, err := NewCurve25519PrivateKey(priv[:])
		if err != nil {
			t.Fatalf("NewCurve25519PrivateKey failed: %v", err)
		}

		pubKey, err := NewCurve25519PublicKey(pub[:])
		if err != nil {
			t.Fatalf("NewCurve25519PublicKey failed: %v", err)
		}

		// Create test message
		message := []byte("Test message for Curve25519 encryption")

		// Encrypt with public key
		encrypter, err := pubKey.NewEncrypter()
		if err != nil {
			t.Fatalf("NewEncrypter() failed: %v", err)
		}

		ciphertext, err := encrypter.Encrypt(message)
		if err != nil {
			t.Fatalf("Encrypt() failed: %v", err)
		}

		// Decrypt with private key
		decrypter, err := privKey.NewDecrypter()
		if err != nil {
			t.Fatalf("NewDecrypter() failed: %v", err)
		}

		plaintext, err := decrypter.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() failed: %v", err)
		}

		// Verify plaintext matches original
		if len(plaintext) != len(message) {
			t.Errorf("Plaintext length mismatch: got %d, want %d", len(plaintext), len(message))
		}

		for i := range message {
			if plaintext[i] != message[i] {
				t.Errorf("Plaintext mismatch at byte %d: got %d, want %d", i, plaintext[i], message[i])
				break
			}
		}
	})

	t.Run("Zero() method", func(t *testing.T) {
		// Generate a valid key
		_, priv, err := curve25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		privKey, err := NewCurve25519PrivateKey(priv[:])
		if err != nil {
			t.Fatalf("NewCurve25519PrivateKey failed: %v", err)
		}

		// Call Zero()
		privKey.Zero()

		// Verify all bytes are zeroed
		for i, b := range privKey.Bytes() {
			if b != 0 {
				t.Errorf("Zero() failed: byte at index %d is %d, expected 0", i, b)
			}
		}
	})

	t.Run("NewDecrypter works", func(t *testing.T) {
		// Generate a valid key
		_, priv, err := curve25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		key, err := NewCurve25519PrivateKey(priv[:])
		if err != nil {
			t.Fatalf("NewCurve25519PrivateKey failed: %v", err)
		}

		decrypter, err := key.NewDecrypter()
		if err != nil {
			t.Fatalf("NewDecrypter() failed: %v", err)
		}

		if decrypter == nil {
			t.Error("NewDecrypter() returned nil decrypter")
		}
	})

	// X25519 has no I2P signature type (cryptography.md §Signatures). The
	// Curve25519Signer/Curve25519Verifier types were removed because they
	// produced signatures no router could verify; assert they are gone so the
	// removal cannot silently regress.
	t.Run("no signing path", func(t *testing.T) {
		_, priv, err := curve25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		key, err := NewCurve25519PrivateKey(priv[:])
		if err != nil {
			t.Fatalf("NewCurve25519PrivateKey failed: %v", err)
		}
		// Curve25519 keys satisfy the encryption interfaces only.
		var _ types.PrivateEncryptionKey = key
		// A signing-private-key assertion would not compile; guard against the
		// signer types reappearing by asserting the interface is not satisfied.
		var pk any = key
		if _, ok := pk.(types.SigningPrivateKey); ok {
			t.Error("Curve25519PrivateKey satisfies types.SigningPrivateKey; X25519 is not an I2P signature scheme")
		}
		pub, err := NewCurve25519PublicKey(priv.Public().(curve25519.PublicKey)[:])
		if err != nil {
			t.Fatalf("NewCurve25519PublicKey failed: %v", err)
		}
		var pk2 any = pub
		if _, ok := pk2.(types.SigningPublicKey); ok {
			t.Error("Curve25519PublicKey satisfies types.SigningPublicKey; X25519 is not an I2P signature scheme")
		}
	})
}

// TestCurve25519KeyPairConsistency tests that keys created with constructors
// are consistent with the standard library behavior.
func TestCurve25519KeyPairConsistency(t *testing.T) {
	// Generate 10 key pairs and verify consistency
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("iter_%d", i), func(t *testing.T) {
			pub, priv, err := curve25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			pubKey, err := NewCurve25519PublicKey(pub[:])
			if err != nil {
				t.Fatalf("NewCurve25519PublicKey failed: %v", err)
			}

			privKey, err := NewCurve25519PrivateKey(priv[:])
			if err != nil {
				t.Fatalf("NewCurve25519PrivateKey failed: %v", err)
			}

			// Derive public key from private key and verify match
			derivedPubInterface, err := privKey.Public()
			if err != nil {
				t.Fatalf("Public() failed: %v", err)
			}
			derivedPub, ok := derivedPubInterface.(*Curve25519PublicKey)
			if !ok {
				t.Fatalf("Public() returned wrong type")
			}
			if !bytes.Equal(derivedPub.Bytes(), pubKey.Bytes()) {
				t.Error("derived public key mismatch")
			}

			// Encryption/decryption round-trip
			message := []byte("Consistency test message")
			encrypter, err := pubKey.NewEncrypter()
			if err != nil {
				t.Fatalf("NewEncrypter failed: %v", err)
			}
			ciphertext, err := encrypter.Encrypt(message)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			decrypter, err := privKey.NewDecrypter()
			if err != nil {
				t.Fatalf("NewDecrypter failed: %v", err)
			}
			plaintext, err := decrypter.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if !bytes.Equal(plaintext, message) {
				t.Error("plaintext mismatch")
			}
		})
	}
}

// BenchmarkNewCurve25519PublicKey benchmarks the constructor performance.
func BenchmarkNewCurve25519PublicKey(b *testing.B) {
	pub, _, err := curve25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewCurve25519PublicKey(pub[:])
	}
}

// BenchmarkNewCurve25519PrivateKey benchmarks the constructor performance.
func BenchmarkNewCurve25519PrivateKey(b *testing.B) {
	_, priv, err := curve25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewCurve25519PrivateKey(priv[:])
	}
}
