package curve25519

import (
	"crypto/rand"
	"testing"

	curve25519 "go.step.sm/crypto/x25519"
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

	t.Run("NewSigner works", func(t *testing.T) {
		// Generate a valid key
		_, priv, err := curve25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		key, err := NewCurve25519PrivateKey(priv[:])
		if err != nil {
			t.Fatalf("NewCurve25519PrivateKey failed: %v", err)
		}

		signer, err := key.NewSigner()
		if err != nil {
			t.Fatalf("NewSigner() failed: %v", err)
		}

		if signer == nil {
			t.Error("NewSigner() returned nil signer")
		}
	})
}

// TestCurve25519KeyPairConsistency tests that keys created with constructors
// are consistent with the standard library behavior.
func TestCurve25519KeyPairConsistency(t *testing.T) {
	// Generate 10 key pairs and verify consistency
	for i := 0; i < 10; i++ {
		pub, priv, err := curve25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Iteration %d: failed to generate key: %v", i, err)
		}

		pubKey, err := NewCurve25519PublicKey(pub[:])
		if err != nil {
			t.Fatalf("Iteration %d: NewCurve25519PublicKey failed: %v", i, err)
		}

		privKey, err := NewCurve25519PrivateKey(priv[:])
		if err != nil {
			t.Fatalf("Iteration %d: NewCurve25519PrivateKey failed: %v", i, err)
		}

		// Derive public key from private key
		derivedPubInterface, err := privKey.Public()
		if err != nil {
			t.Fatalf("Iteration %d: Public() failed: %v", i, err)
		}

		derivedPub, ok := derivedPubInterface.(*Curve25519PublicKey)
		if !ok {
			t.Fatalf("Iteration %d: Public() returned wrong type", i)
		}

		// Verify derived public key matches original
		if len(derivedPub.Bytes()) != len(pubKey.Bytes()) {
			t.Errorf("Iteration %d: derived public key length mismatch", i)
			continue
		}

		for j := 0; j < len(pubKey.Bytes()); j++ {
			if derivedPub.Bytes()[j] != pubKey.Bytes()[j] {
				t.Errorf("Iteration %d: derived public key mismatch at byte %d", i, j)
				break
			}
		}

		// Test encryption/decryption round-trip
		message := []byte("Consistency test message")

		encrypter, err := pubKey.NewEncrypter()
		if err != nil {
			t.Fatalf("Iteration %d: NewEncrypter failed: %v", i, err)
		}

		ciphertext, err := encrypter.Encrypt(message)
		if err != nil {
			t.Fatalf("Iteration %d: Encrypt failed: %v", i, err)
		}

		decrypter, err := privKey.NewDecrypter()
		if err != nil {
			t.Fatalf("Iteration %d: NewDecrypter failed: %v", i, err)
		}

		plaintext, err := decrypter.Decrypt(ciphertext)
		if err != nil {
			t.Errorf("Iteration %d: Decrypt failed: %v", i, err)
			continue
		}

		if len(plaintext) != len(message) {
			t.Errorf("Iteration %d: plaintext length mismatch", i)
			continue
		}

		for j := range message {
			if plaintext[j] != message[j] {
				t.Errorf("Iteration %d: plaintext mismatch at byte %d", i, j)
				break
			}
		}
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
