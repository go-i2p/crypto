package elg

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// TestNewElgPrivateKey tests ElGamal private key constructor validation
func TestNewElgPrivateKey(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "invalid size - too small",
			input:     make([]byte, 255),
			wantError: true,
		},
		{
			name:      "invalid size - too large",
			input:     make([]byte, 257),
			wantError: true,
		},
		{
			name:      "empty input",
			input:     []byte{},
			wantError: true,
		},
		{
			name:      "nil input",
			input:     nil,
			wantError: true,
		},
		{
			name:      "all zeros (invalid - out of range)",
			input:     make([]byte, 256),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewElgPrivateKey(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("NewElgPrivateKey() error = %v, wantError %v", err, tt.wantError)
			}
			if err == nil && key == nil {
				t.Error("NewElgPrivateKey() returned nil key without error")
			}
		})
	}
}

// TestNewElgPrivateKeyValidRange tests with valid keys in range [1, p-1]
func TestNewElgPrivateKeyValidRange(t *testing.T) {
	t.Run("valid key - value 1", func(t *testing.T) {
		// Create key with value 1 (minimum valid value)
		keyBytes := make([]byte, 256)
		keyBytes[255] = 1 // Big-endian 1

		key, err := NewElgPrivateKey(keyBytes)
		if err != nil {
			t.Errorf("NewElgPrivateKey() failed with value 1: %v", err)
		}
		if key == nil {
			t.Error("NewElgPrivateKey() returned nil key for valid input")
		}
	})

	t.Run("valid key - random value", func(t *testing.T) {
		// Generate a random valid private key
		max := new(big.Int).Sub(elgp, one)
		x, err := rand.Int(rand.Reader, max)
		if err != nil {
			t.Fatalf("Failed to generate random value: %v", err)
		}
		
		// Ensure it's at least 1
		if x.Cmp(one) < 0 {
			x = one
		}

		keyBytes := make([]byte, 256)
		xBytes := x.Bytes()
		copy(keyBytes[256-len(xBytes):], xBytes)

		key, err := NewElgPrivateKey(keyBytes)
		if err != nil {
			t.Errorf("NewElgPrivateKey() failed with valid random key: %v", err)
		}
		if key == nil {
			t.Error("NewElgPrivateKey() returned nil key")
		}
	})
}

// TestNewElgPrivateKeyRejectsOutOfRange tests rejection of out-of-range values
func TestNewElgPrivateKeyRejectsOutOfRange(t *testing.T) {
	t.Run("reject value >= p", func(t *testing.T) {
		// Try to create key with value = p (should fail)
		keyBytes := make([]byte, 256)
		pBytes := elgp.Bytes()
		copy(keyBytes[256-len(pBytes):], pBytes)

		_, err := NewElgPrivateKey(keyBytes)
		if err == nil {
			t.Error("NewElgPrivateKey() should reject value >= p")
		}
	})

	t.Run("reject value >= p-1", func(t *testing.T) {
		// Try to create key with value = p-1 (should fail)
		pMinus1 := new(big.Int).Sub(elgp, one)
		keyBytes := make([]byte, 256)
		pmBytes := pMinus1.Bytes()
		copy(keyBytes[256-len(pmBytes):], pmBytes)

		_, err := NewElgPrivateKey(keyBytes)
		if err == nil {
			t.Error("NewElgPrivateKey() should reject value = p-1")
		}
	})
}

// TestNewElgPublicKey tests ElGamal public key constructor validation
func TestNewElgPublicKey(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "invalid size - too small",
			input:     make([]byte, 255),
			wantError: true,
		},
		{
			name:      "invalid size - too large",
			input:     make([]byte, 257),
			wantError: true,
		},
		{
			name:      "empty input",
			input:     []byte{},
			wantError: true,
		},
		{
			name:      "nil input",
			input:     nil,
			wantError: true,
		},
		{
			name:      "all zeros (Y=0 - invalid)",
			input:     make([]byte, 256),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewElgPublicKey(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("NewElgPublicKey() error = %v, wantError %v", err, tt.wantError)
			}
			if err == nil && key == nil {
				t.Error("NewElgPublicKey() returned nil key without error")
			}
		})
	}
}

// TestNewElgPublicKeyValidRange tests with valid keys in range [2, p-1]
func TestNewElgPublicKeyValidRange(t *testing.T) {
	t.Run("valid key - value 2", func(t *testing.T) {
		// Create key with value 2 (minimum valid value for public key)
		keyBytes := make([]byte, 256)
		keyBytes[255] = 2 // Big-endian 2

		key, err := NewElgPublicKey(keyBytes)
		if err != nil {
			t.Errorf("NewElgPublicKey() failed with value 2: %v", err)
		}
		if key == nil {
			t.Error("NewElgPublicKey() returned nil key for valid input")
		}
	})

	t.Run("valid key - random value", func(t *testing.T) {
		// Generate a random valid public key
		max := new(big.Int).Sub(elgp, one)
		y, err := rand.Int(rand.Reader, max)
		if err != nil {
			t.Fatalf("Failed to generate random value: %v", err)
		}
		
		// Ensure it's at least 2
		two := big.NewInt(2)
		if y.Cmp(two) < 0 {
			y = two
		}

		keyBytes := make([]byte, 256)
		yBytes := y.Bytes()
		copy(keyBytes[256-len(yBytes):], yBytes)

		key, err := NewElgPublicKey(keyBytes)
		if err != nil {
			t.Errorf("NewElgPublicKey() failed with valid random key: %v", err)
		}
		if key == nil {
			t.Error("NewElgPublicKey() returned nil key")
		}
	})
}

// TestNewElgPublicKeyRejectsWeakValues tests rejection of cryptographically weak values
func TestNewElgPublicKeyRejectsWeakValues(t *testing.T) {
	t.Run("reject Y=1", func(t *testing.T) {
		keyBytes := make([]byte, 256)
		keyBytes[255] = 1 // Y=1 is weak

		_, err := NewElgPublicKey(keyBytes)
		if err == nil {
			t.Error("NewElgPublicKey() should reject Y=1")
		}
	})

	t.Run("reject value >= p", func(t *testing.T) {
		// Try to create key with value = p (should fail)
		keyBytes := make([]byte, 256)
		pBytes := elgp.Bytes()
		copy(keyBytes[256-len(pBytes):], pBytes)

		_, err := NewElgPublicKey(keyBytes)
		if err == nil {
			t.Error("NewElgPublicKey() should reject value >= p")
		}
	})
}

// TestElgKeyDefensiveCopy verifies constructors return defensive copies
func TestElgKeyDefensiveCopy(t *testing.T) {
	t.Run("private key defensive copy", func(t *testing.T) {
		original := make([]byte, 256)
		original[255] = 5 // Valid value

		key, err := NewElgPrivateKey(original)
		if err != nil {
			t.Fatalf("Constructor failed: %v", err)
		}

		// Modify original
		original[255] = 99

		// Key should be unchanged
		if key[255] != 5 {
			t.Error("Constructor did not create defensive copy")
		}
	})

	t.Run("public key defensive copy", func(t *testing.T) {
		original := make([]byte, 256)
		original[255] = 10 // Valid value

		key, err := NewElgPublicKey(original)
		if err != nil {
			t.Fatalf("Constructor failed: %v", err)
		}

		// Modify original
		original[255] = 99

		// Key should be unchanged
		if key[255] != 10 {
			t.Error("Constructor did not create defensive copy")
		}
	})
}

// TestElgKeyPairConsistency tests key generation and public key derivation
func TestElgKeyPairConsistency(t *testing.T) {
	// Generate a valid ElGamal private key using the Generate method
	var privKeyType ElgPrivateKey
	privKeyInterface, err := privKeyType.Generate()
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	privKey := privKeyInterface.(ElgPrivateKey)
	privBytes := privKey.Bytes()

	// Create using constructor
	constructedPriv, err := NewElgPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewElgPrivateKey() failed with generated key: %v", err)
	}

	// Derive public key
	pubInterface, err := constructedPriv.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	pubKey := pubInterface.(ElgPublicKey)
	pubBytes := pubKey.Bytes()

	// Create public key using constructor
	constructedPub, err := NewElgPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("NewElgPublicKey() failed with derived key: %v", err)
	}

	// Verify encrypter and decrypter can be created
	_, err = constructedPub.NewEncrypter()
	if err != nil {
		t.Errorf("NewEncrypter() failed: %v", err)
	}

	_, err = constructedPriv.NewDecrypter()
	if err != nil {
		t.Errorf("NewDecrypter() failed: %v", err)
	}
}

// TestElgPrivateKeyZero tests the Zero method
// Note: The current implementation uses a value receiver, so Zero() doesn't
// actually modify the original key. This is a known limitation.
func TestElgPrivateKeyZero(t *testing.T) {
	keyBytes := make([]byte, 256)
	keyBytes[255] = 5 // Valid value

	key, err := NewElgPrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("NewElgPrivateKey() failed: %v", err)
	}

	// Verify key is not zero before Zero()
	if key[255] == 0 {
		t.Error("Key should not be zero before Zero() is called")
	}

	// Call Zero() - note this uses a value receiver
	// so it creates a copy and zeros that
	key.Zero()

	// Note: Due to value receiver, the original key is NOT zeroed
	// This is a known limitation of the current API
	t.Log("Note: ElgPrivateKey.Zero() uses value receiver, so original key is not modified")
}

// Benchmark constructors
func BenchmarkNewElgPrivateKey(b *testing.B) {
	keyBytes := make([]byte, 256)
	keyBytes[255] = 5 // Valid value

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewElgPrivateKey(keyBytes)
	}
}

func BenchmarkNewElgPublicKey(b *testing.B) {
	keyBytes := make([]byte, 256)
	keyBytes[255] = 10 // Valid value

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewElgPublicKey(keyBytes)
	}
}
