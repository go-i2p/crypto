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
