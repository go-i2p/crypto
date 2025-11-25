package dsa

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// TestNewDSAPrivateKey tests the DSA private key constructor with various invalid inputs
func TestNewDSAPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "invalid size - too small",
			input:   make([]byte, 19),
			wantErr: true,
		},
		{
			name:    "invalid size - too large",
			input:   make([]byte, 21),
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "nil input",
			input:   nil,
			wantErr: true,
		},
		{
			name:    "all zeros (invalid)",
			input:   make([]byte, 20),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDSAPrivateKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDSAPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNewDSAPrivateKeyValidRange tests that valid keys within range are accepted
func TestNewDSAPrivateKeyValidRange(t *testing.T) {
	tests := []struct {
		name  string
		setup func() []byte
	}{
		{
			name: "valid key - value 1",
			setup: func() []byte {
				data := make([]byte, 20)
				data[19] = 1 // Smallest valid private key
				return data
			},
		},
		{
			name: "valid key - random value",
			setup: func() []byte {
				data := make([]byte, 20)
				_, _ = rand.Read(data)
				// Ensure it's less than p by setting high bytes to 0
				for i := 0; i < 10; i++ {
					data[i] = 0
				}
				data[19] |= 1 // Ensure non-zero
				return data
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setup()
			key, err := NewDSAPrivateKey(data)
			if err != nil {
				t.Errorf("NewDSAPrivateKey() unexpected error = %v", err)
			}
			// Verify defensive copy
			if &key[0] == &data[0] {
				t.Error("Expected defensive copy, got same underlying array")
			}
		})
	}
}

// TestNewDSAPrivateKeyRejectsOutOfRange tests that keys >= p are rejected
func TestNewDSAPrivateKeyRejectsOutOfRange(t *testing.T) {
	tests := []struct {
		name  string
		setup func() []byte
	}{
		{
			name: "reject value >= p",
			setup: func() []byte {
				// Use p itself (should be rejected)
				// dsap is 128 bytes, private key is 20 bytes
				// So we need to take the lower 20 bytes of p, but that would be valid
				// Instead, create a value that's definitely >= p in the 20-byte space
				// Since dsaq is 160-bit (20 bytes), use q as the limit
				data := dsaq.Bytes()
				// Pad to 20 bytes if needed
				if len(data) < 20 {
					padded := make([]byte, 20)
					copy(padded[20-len(data):], data)
					data = padded
				}
				return data
			},
		},
		{
			name: "reject max 20-byte value",
			setup: func() []byte {
				// All 0xFF - this is definitely >= dsaq
				data := make([]byte, 20)
				for i := range data {
					data[i] = 0xFF
				}
				return data
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setup()
			_, err := NewDSAPrivateKey(data)
			if err == nil {
				t.Error("NewDSAPrivateKey() expected error for out-of-range key, got nil")
			}
		})
	}
}

// TestNewDSAPublicKey tests the DSA public key constructor with various invalid inputs
func TestNewDSAPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "invalid size - too small",
			input:   make([]byte, 127),
			wantErr: true,
		},
		{
			name:    "invalid size - too large",
			input:   make([]byte, 129),
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "nil input",
			input:   nil,
			wantErr: true,
		},
		{
			name:    "all zeros (Y=0 - invalid)",
			input:   make([]byte, 128),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDSAPublicKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDSAPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNewDSAPublicKeyValidRange tests that valid keys within range are accepted
func TestNewDSAPublicKeyValidRange(t *testing.T) {
	tests := []struct {
		name  string
		setup func() []byte
	}{
		{
			name: "valid key - value 2",
			setup: func() []byte {
				data := make([]byte, 128)
				data[127] = 2 // Smallest valid public key (Y >= 2)
				return data
			},
		},
		{
			name: "valid key - generator g",
			setup: func() []byte {
				// Use the DSA generator g as a valid public key
				gBytes := dsag.Bytes()
				data := make([]byte, 128)
				copy(data[128-len(gBytes):], gBytes)
				return data
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setup()
			key, err := NewDSAPublicKey(data)
			if err != nil {
				t.Errorf("NewDSAPublicKey() unexpected error = %v", err)
			}
			// Verify defensive copy
			if &key[0] == &data[0] {
				t.Error("Expected defensive copy, got same underlying array")
			}
		})
	}
}

// TestNewDSAPublicKeyRejectsWeakValues tests that Y=1 and Y>=p are rejected
func TestNewDSAPublicKeyRejectsWeakValues(t *testing.T) {
	tests := []struct {
		name  string
		setup func() []byte
	}{
		{
			name: "reject Y=1",
			setup: func() []byte {
				data := make([]byte, 128)
				data[127] = 1 // Y=1 is cryptographically weak
				return data
			},
		},
		{
			name: "reject value >= p",
			setup: func() []byte {
				// Use p itself (should be rejected)
				pBytes := dsap.Bytes()
				data := make([]byte, 128)
				copy(data[128-len(pBytes):], pBytes)
				return data
			},
		},
		{
			name: "reject value > p",
			setup: func() []byte {
				// Create p+1
				pPlusOne := new(big.Int).Add(dsap, big.NewInt(1))
				pBytes := pPlusOne.Bytes()
				data := make([]byte, 128)
				if len(pBytes) <= 128 {
					copy(data[128-len(pBytes):], pBytes)
				}
				return data
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setup()
			_, err := NewDSAPublicKey(data)
			if err == nil {
				t.Error("NewDSAPublicKey() expected error for weak/invalid key, got nil")
			}
		})
	}
}

// TestDSAKeyDefensiveCopy verifies that constructors return defensive copies
func TestDSAKeyDefensiveCopy(t *testing.T) {
	t.Run("private key defensive copy", func(t *testing.T) {
		original := make([]byte, 20)
		original[19] = 42

		key, err := NewDSAPrivateKey(original)
		if err != nil {
			t.Fatalf("NewDSAPrivateKey() failed: %v", err)
		}

		// Modify original
		original[19] = 99

		// Key should be unchanged
		if key[19] == 99 {
			t.Error("Modifying input modified the key - defensive copy not working")
		}
		if key[19] != 42 {
			t.Errorf("Key value = %d, want 42", key[19])
		}
	})

	t.Run("public key defensive copy", func(t *testing.T) {
		original := make([]byte, 128)
		original[127] = 42

		key, err := NewDSAPublicKey(original)
		if err != nil {
			t.Fatalf("NewDSAPublicKey() failed: %v", err)
		}

		// Modify original
		original[127] = 99

		// Key should be unchanged
		if key[127] == 99 {
			t.Error("Modifying input modified the key - defensive copy not working")
		}
		if key[127] != 42 {
			t.Errorf("Key value = %d, want 42", key[127])
		}
	})
}

// TestDSAKeyPairConsistency tests that a generated key pair works with the constructors
func TestDSAKeyPairConsistency(t *testing.T) {
	// Generate a key pair using the existing Generate method
	var zeroKey DSAPrivateKey
	privKeyInterface, err := zeroKey.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Convert interface back to concrete type
	privKey, ok := privKeyInterface.(DSAPrivateKey)
	if !ok {
		t.Fatalf("Generate() returned wrong type: %T", privKeyInterface)
	}

	// Convert to bytes and reconstruct using constructor
	privBytes := privKey.Bytes()
	reconstructedPriv, err := NewDSAPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewDSAPrivateKey() failed on generated key: %v", err)
	}

	// Verify they match
	for i := range reconstructedPriv {
		if reconstructedPriv[i] != privBytes[i] {
			t.Errorf("Reconstructed private key byte %d = %d, want %d", i, reconstructedPriv[i], privBytes[i])
			break
		}
	}

	// Get public key
	pubKeyInterface, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	// Convert interface back to concrete type
	pubKey, ok := pubKeyInterface.(DSAPublicKey)
	if !ok {
		t.Fatalf("Public() returned wrong type: %T", pubKeyInterface)
	}

	// Convert to bytes and reconstruct using constructor
	pubBytes := pubKey.Bytes()
	reconstructedPub, err := NewDSAPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("NewDSAPublicKey() failed on generated key: %v", err)
	}

	// Verify they match
	for i := range reconstructedPub {
		if reconstructedPub[i] != pubBytes[i] {
			t.Errorf("Reconstructed public key byte %d = %d, want %d", i, reconstructedPub[i], pubBytes[i])
			break
		}
	}
}

// TestDSAPrivateKeyZero tests the Zero method
// Note: The current implementation uses a pointer receiver for Zero()
func TestDSAPrivateKeyZero(t *testing.T) {
	keyBytes := make([]byte, 20)
	keyBytes[19] = 5 // Valid value

	key, err := NewDSAPrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("NewDSAPrivateKey() failed: %v", err)
	}

	// Verify key is not zero before Zero()
	if key[19] == 0 {
		t.Error("Key should not be zero before Zero() is called")
	}

	// Call Zero() - this uses a pointer receiver
	key.Zero()

	// Verify key is zeroed
	for i, b := range key {
		if b != 0 {
			t.Errorf("Key byte %d = %d, want 0 after Zero()", i, b)
			break
		}
	}
}
