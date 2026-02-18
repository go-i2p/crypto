package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
)

func TestEd25519(t *testing.T) {
	var pubKey Ed25519PublicKey

	signer := new(Ed25519Signer)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Log("Failed to generate ed25519 test key")
		t.Fail()
	}
	pubKey = []byte(pub)
	signer.k = []byte(priv)

	message := make([]byte, 123)
	io.ReadFull(rand.Reader, message)

	sig, err := signer.Sign(message)
	if err != nil {
		t.Log("Failed to sign message")
		t.Fail()
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Logf("Error from verifier: %s", err)
		t.Fail()
	}

	err = verifier.Verify(message, sig)
	if err != nil {
		t.Log("Failed to verify message")
		t.Fail()
	}
}

// TestEd25519RFC8032Interop verifies that Sign()/Verify() produce standard
// RFC 8032 PureEdDSA signatures that are interoperable with Go's stdlib
// ed25519.Sign/ed25519.Verify (and by extension Java I2P and i2pd).
func TestEd25519RFC8032Interop(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Failed to generate key:", err)
	}

	message := make([]byte, 256)
	io.ReadFull(rand.Reader, message)

	// Sign with our wrapper
	signer := &Ed25519Signer{k: []byte(priv)}
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Signer.Sign failed:", err)
	}

	// Verify with stdlib directly — this proves RFC 8032 interop
	if !ed25519.Verify(pub, message, sig) {
		t.Fatal("Signature produced by Ed25519Signer.Sign() is NOT verifiable by stdlib ed25519.Verify — not RFC 8032 compliant")
	}

	// Sign with stdlib directly
	stdlibSig := ed25519.Sign(priv, message)

	// Verify with our wrapper — proves we accept standard signatures
	pubKey := Ed25519PublicKey(pub)
	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}
	if err := verifier.Verify(message, stdlibSig); err != nil {
		t.Fatal("Ed25519Verifier.Verify() rejects a standard ed25519.Sign() signature — not RFC 8032 compliant")
	}
}

// TestEd25519PublicKeyBytes tests the Bytes() method to ensure it returns the correct key data.
// This is a regression test for the bug where Ed25519PublicKey.Bytes() returned empty slices.
func TestEd25519PublicKeyBytes(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() Ed25519PublicKey
		expected int
		wantErr  bool
	}{
		{
			name: "generated key returns 32 bytes",
			setup: func() Ed25519PublicKey {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return Ed25519PublicKey(pub)
			},
			expected: ed25519.PublicKeySize,
			wantErr:  false,
		},
		{
			name: "key created from bytes returns 32 bytes",
			setup: func() Ed25519PublicKey {
				keyData := make([]byte, ed25519.PublicKeySize)
				io.ReadFull(rand.Reader, keyData)
				key, err := CreateEd25519PublicKeyFromBytes(keyData)
				if err != nil {
					t.Fatal(err)
				}
				return key
			},
			expected: ed25519.PublicKeySize,
			wantErr:  false,
		},
		{
			name: "manual construction returns correct bytes",
			setup: func() Ed25519PublicKey {
				keyData := make([]byte, ed25519.PublicKeySize)
				for i := range keyData {
					keyData[i] = byte(i)
				}
				return Ed25519PublicKey(keyData)
			},
			expected: ed25519.PublicKeySize,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey := tt.setup()

			// Test Len() method
			if got := pubKey.Len(); got != tt.expected {
				t.Errorf("Len() = %d, want %d", got, tt.expected)
			}

			// Test Bytes() method
			bytes := pubKey.Bytes()
			if len(bytes) != tt.expected {
				t.Errorf("Bytes() length = %d, want %d", len(bytes), tt.expected)
			}

			// Verify the bytes are not empty
			if len(bytes) > 0 {
				allZero := true
				for _, b := range bytes {
					if b != 0 {
						allZero = false
						break
					}
				}
				// For randomly generated keys, it's extremely unlikely all bytes are zero
				if allZero && tt.name == "generated key returns 32 bytes" {
					t.Error("Bytes() returned all zeros for a generated key (very unlikely)")
				}
			}
		})
	}
}

// TestEd25519PublicKeyBytesRoundTrip tests that serialization with Bytes() preserves data.
// This simulates the I2P Destination serialization scenario from the bug report.
func TestEd25519PublicKeyBytesRoundTrip(t *testing.T) {
	// Create original key data
	originalData := make([]byte, ed25519.PublicKeySize)
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	// Create Ed25519 public key from data
	pubKey, err := CreateEd25519PublicKeyFromBytes(originalData)
	if err != nil {
		t.Fatalf("CreateEd25519PublicKeyFromBytes failed: %v", err)
	}

	// Serialize back to bytes
	serialized := pubKey.Bytes()

	// Verify length
	if len(serialized) != ed25519.PublicKeySize {
		t.Errorf("Serialized length = %d, want %d", len(serialized), ed25519.PublicKeySize)
	}

	// Verify content matches original
	for i := 0; i < ed25519.PublicKeySize; i++ {
		if i < len(serialized) && serialized[i] != originalData[i] {
			t.Errorf("Byte mismatch at index %d: got %d, want %d", i, serialized[i], originalData[i])
		}
	}

	// Parse again from serialized data
	reparsed, err := CreateEd25519PublicKeyFromBytes(serialized)
	if err != nil {
		t.Fatalf("Re-parsing failed: %v", err)
	}

	// Verify the reparsed key matches
	if len(reparsed.Bytes()) != ed25519.PublicKeySize {
		t.Errorf("Reparsed key length = %d, want %d", len(reparsed.Bytes()), ed25519.PublicKeySize)
	}
}

// TestEd25519PublicKeyNilSliceBug reproduces the bug from the issue report.
// This tests the scenario where a nil slice is declared and copy() is attempted.
// This is the ACTUAL bug: declaring "var key Ed25519PublicKey" creates a nil slice.
func TestEd25519PublicKeyNilSliceBug(t *testing.T) {
	// Reproduce the bug pattern from the consuming code
	keyData := make([]byte, 32)
	for i := range keyData {
		keyData[i] = byte(i)
	}

	// This is the BUGGY pattern: declaring a var creates a nil slice
	var buggyKey Ed25519PublicKey
	copied := copy(buggyKey[:], keyData) // This will panic or copy 0 bytes
	t.Logf("Buggy pattern: copied %d bytes to nil slice", copied)
	t.Logf("Buggy key Len(): %d", buggyKey.Len())
	t.Logf("Buggy key Bytes() length: %d", len(buggyKey.Bytes()))

	if len(buggyKey.Bytes()) != 0 {
		t.Error("Expected nil slice to have 0 length, but got non-zero")
	}

	// This is the CORRECT pattern: create the slice first
	correctKey := make(Ed25519PublicKey, 32)
	copy(correctKey[:], keyData)
	t.Logf("Correct pattern: key Len(): %d", correctKey.Len())
	t.Logf("Correct pattern: key Bytes() length: %d", len(correctKey.Bytes()))

	if len(correctKey.Bytes()) != 32 {
		t.Errorf("Expected correct key to have 32 bytes, got %d", len(correctKey.Bytes()))
	}
}

// TestNewEd25519PublicKey tests the mandatory constructor for Ed25519 public keys.
func TestNewEd25519PublicKey(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		data := make([]byte, 32)
		io.ReadFull(rand.Reader, data)

		key, err := NewEd25519PublicKey(data)
		if err != nil {
			t.Fatalf("NewEd25519PublicKey failed: %v", err)
		}

		if key.Len() != 32 {
			t.Errorf("Len() = %d, want 32", key.Len())
		}

		if len(key.Bytes()) != 32 {
			t.Errorf("Bytes() length = %d, want 32", len(key.Bytes()))
		}

		// Verify bytes match input
		for i, b := range key.Bytes() {
			if b != data[i] {
				t.Errorf("Byte mismatch at index %d: got %d, want %d", i, b, data[i])
				break
			}
		}
	})

	t.Run("invalid size - too short", func(t *testing.T) {
		data := make([]byte, 16)
		_, err := NewEd25519PublicKey(data)
		if err == nil {
			t.Error("Expected error for 16-byte key, got nil")
		}
	})

	t.Run("invalid size - too long", func(t *testing.T) {
		data := make([]byte, 64)
		_, err := NewEd25519PublicKey(data)
		if err == nil {
			t.Error("Expected error for 64-byte key, got nil")
		}
	})

	t.Run("nil input", func(t *testing.T) {
		_, err := NewEd25519PublicKey(nil)
		if err == nil {
			t.Error("Expected error for nil input, got nil")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := NewEd25519PublicKey([]byte{})
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

		key, err := NewEd25519PublicKey(data)
		if err != nil {
			t.Fatalf("NewEd25519PublicKey failed: %v", err)
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
}

// TestNewEd25519PrivateKey tests the mandatory constructor for Ed25519 private keys.
func TestNewEd25519PrivateKey(t *testing.T) {
	t.Run("valid 64-byte key", func(t *testing.T) {
		// Generate a valid key pair
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		key, err := NewEd25519PrivateKey(priv)
		if err != nil {
			t.Fatalf("NewEd25519PrivateKey failed: %v", err)
		}

		if key.Len() != 64 {
			t.Errorf("Len() = %d, want 64", key.Len())
		}

		if len(key.Bytes()) != 64 {
			t.Errorf("Bytes() length = %d, want 64", len(key.Bytes()))
		}
	})

	t.Run("invalid size - too short", func(t *testing.T) {
		data := make([]byte, 32)
		_, err := NewEd25519PrivateKey(data)
		if err == nil {
			t.Error("Expected error for 32-byte private key, got nil")
		}
	})

	t.Run("invalid size - too long", func(t *testing.T) {
		data := make([]byte, 128)
		_, err := NewEd25519PrivateKey(data)
		if err == nil {
			t.Error("Expected error for 128-byte private key, got nil")
		}
	})

	t.Run("nil input", func(t *testing.T) {
		_, err := NewEd25519PrivateKey(nil)
		if err == nil {
			t.Error("Expected error for nil input, got nil")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := NewEd25519PrivateKey([]byte{})
		if err == nil {
			t.Error("Expected error for empty input, got nil")
		}
	})

	t.Run("public key derivation", func(t *testing.T) {
		// Generate a valid key pair
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		privKey, err := NewEd25519PrivateKey(priv)
		if err != nil {
			t.Fatalf("NewEd25519PrivateKey failed: %v", err)
		}

		// Derive public key
		derivedPub, err := privKey.Public()
		if err != nil {
			t.Fatalf("Public() failed: %v", err)
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

	t.Run("sign and verify round-trip", func(t *testing.T) {
		// Generate a valid key pair
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		privKey, err := NewEd25519PrivateKey(priv)
		if err != nil {
			t.Fatalf("NewEd25519PrivateKey failed: %v", err)
		}

		pubKey, err := NewEd25519PublicKey(pub)
		if err != nil {
			t.Fatalf("NewEd25519PublicKey failed: %v", err)
		}

		// Create test message
		message := []byte("Test message for Ed25519 signature")

		// Sign with private key
		signer, err := privKey.NewSigner()
		if err != nil {
			t.Fatalf("NewSigner() failed: %v", err)
		}

		signature, err := signer.Sign(message)
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}

		// Verify with public key
		verifier, err := pubKey.NewVerifier()
		if err != nil {
			t.Fatalf("NewVerifier() failed: %v", err)
		}

		err = verifier.Verify(message, signature)
		if err != nil {
			t.Errorf("Verify() failed: %v", err)
		}
	})

	t.Run("Zero() method", func(t *testing.T) {
		// Generate a valid key
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		privKey, err := NewEd25519PrivateKey(priv)
		if err != nil {
			t.Fatalf("NewEd25519PrivateKey failed: %v", err)
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
}

// TestEd25519KeyPairConsistency tests that keys created with constructors
// are consistent with the standard library behavior.
func TestEd25519KeyPairConsistency(t *testing.T) {
	// Generate 10 key pairs and verify consistency
	for i := 0; i < 10; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Iteration %d: failed to generate key: %v", i, err)
		}

		pubKey, err := NewEd25519PublicKey(pub)
		if err != nil {
			t.Fatalf("Iteration %d: NewEd25519PublicKey failed: %v", i, err)
		}

		privKey, err := NewEd25519PrivateKey(priv)
		if err != nil {
			t.Fatalf("Iteration %d: NewEd25519PrivateKey failed: %v", i, err)
		}

		// Derive public key from private key
		derivedPubInterface, err := privKey.Public()
		if err != nil {
			t.Fatalf("Iteration %d: Public() failed: %v", i, err)
		}

		derivedPub := derivedPubInterface.(Ed25519PublicKey)

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

		// Test signature verification
		message := []byte("Consistency test message")
		signer, err := privKey.NewSigner()
		if err != nil {
			t.Fatalf("Iteration %d: NewSigner failed: %v", i, err)
		}

		sig, err := signer.Sign(message)
		if err != nil {
			t.Fatalf("Iteration %d: Sign failed: %v", i, err)
		}

		verifier, err := pubKey.NewVerifier()
		if err != nil {
			t.Fatalf("Iteration %d: NewVerifier failed: %v", i, err)
		}

		err = verifier.Verify(message, sig)
		if err != nil {
			t.Errorf("Iteration %d: Verify failed: %v", i, err)
		}
	}
}

// BenchmarkNewEd25519PublicKey benchmarks the constructor performance.
func BenchmarkNewEd25519PublicKey(b *testing.B) {
	data := make([]byte, 32)
	io.ReadFull(rand.Reader, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewEd25519PublicKey(data)
	}
}

// BenchmarkNewEd25519PrivateKey benchmarks the constructor performance.
func BenchmarkNewEd25519PrivateKey(b *testing.B) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewEd25519PrivateKey(priv)
	}
}

// TestCreateEd25519PublicKeyDeprecatedFixed tests the fixed createEd25519PublicKey function.
// This test verifies that the bug (expecting 256 bytes instead of 32) has been fixed.
func TestCreateEd25519PublicKeyDeprecatedFixed(t *testing.T) {
	t.Run("valid 32-byte input succeeds after fix", func(t *testing.T) {
		// Generate a valid 32-byte Ed25519 public key
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		// This should now succeed (bug was fixed: 256 → 32 bytes)
		result := createEd25519PublicKey(pub)
		if result == nil {
			t.Error("createEd25519PublicKey returned nil for valid 32-byte input")
		}

		// Verify the key data is correct
		if len(*result) != ed25519.PublicKeySize {
			t.Errorf("createEd25519PublicKey returned key of length %d, want %d", len(*result), ed25519.PublicKeySize)
		}

		// Verify the bytes match the input
		for i, b := range pub {
			if (*result)[i] != b {
				t.Errorf("createEd25519PublicKey returned incorrect key data at index %d", i)
				break
			}
		}
	})

	t.Run("256-byte input fails after fix", func(t *testing.T) {
		// Create 256 bytes of data (the buggy size the function used to accept)
		invalidData := make([]byte, 256)
		io.ReadFull(rand.Reader, invalidData)

		// This should now fail (bug was fixed: no longer accepts 256 bytes)
		result := createEd25519PublicKey(invalidData)
		if result != nil {
			t.Error("createEd25519PublicKey should return nil for 256-byte input after fix, but returned non-nil")
		}
	})

	t.Run("nil input returns nil", func(t *testing.T) {
		result := createEd25519PublicKey(nil)
		if result != nil {
			t.Error("createEd25519PublicKey should return nil for nil input")
		}
	})

	t.Run("empty input returns nil", func(t *testing.T) {
		result := createEd25519PublicKey([]byte{})
		if result != nil {
			t.Error("createEd25519PublicKey should return nil for empty input")
		}
	})

	t.Run("too short input returns nil", func(t *testing.T) {
		shortData := make([]byte, 16)
		io.ReadFull(rand.Reader, shortData)

		result := createEd25519PublicKey(shortData)
		if result != nil {
			t.Error("createEd25519PublicKey should return nil for 16-byte input")
		}
	})

	t.Run("too long input returns nil", func(t *testing.T) {
		longData := make([]byte, 64)
		io.ReadFull(rand.Reader, longData)

		result := createEd25519PublicKey(longData)
		if result != nil {
			t.Error("createEd25519PublicKey should return nil for 64-byte input")
		}
	})

	t.Run("function is deprecated - use NewEd25519PublicKey instead", func(t *testing.T) {
		// This test documents the deprecation - new code should use NewEd25519PublicKey
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		// Old deprecated way (works but logs warning)
		deprecatedKey := createEd25519PublicKey(pub)

		// New preferred way
		newKey, err := NewEd25519PublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}

		// Both should produce equivalent results
		if deprecatedKey == nil {
			t.Fatal("deprecated function returned nil")
		}
		if len(*deprecatedKey) != len(newKey) {
			t.Error("deprecated and new constructors produced keys of different lengths")
		}
	})
}
