package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// TestNewECP256PrivateKey tests P-256 private key constructor validation
func TestNewECP256PrivateKey(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "valid 32-byte key",
			input:     make([]byte, 32),
			wantError: true, // all zeros is invalid
		},
		{
			name:      "invalid size - too small",
			input:     make([]byte, 31),
			wantError: true,
		},
		{
			name:      "invalid size - too large",
			input:     make([]byte, 33),
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewECP256PrivateKey(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("NewECP256PrivateKey() error = %v, wantError %v", err, tt.wantError)
			}
			if err == nil && key == nil {
				t.Error("NewECP256PrivateKey() returned nil key without error")
			}
		})
	}
}

// TestNewECP256PrivateKeyRejectsZero verifies zero key rejection
func TestNewECP256PrivateKeyRejectsZero(t *testing.T) {
	zeroKey := make([]byte, 32)
	key, err := NewECP256PrivateKey(zeroKey)
	if err == nil {
		t.Error("NewECP256PrivateKey() should reject all-zero key")
	}
	if key != nil {
		t.Error("NewECP256PrivateKey() returned non-nil key for invalid input")
	}
}

// TestNewECP256PrivateKeyValidKey tests with a real generated key
func TestNewECP256PrivateKeyValidKey(t *testing.T) {
	// Generate a real P-256 key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Get the private key bytes
	privBytes := privKey.D.Bytes()

	// Pad to 32 bytes if needed
	if len(privBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privBytes):], privBytes)
		privBytes = padded
	}

	key, err := NewECP256PrivateKey(privBytes)
	if err != nil {
		t.Errorf("NewECP256PrivateKey() failed with valid key: %v", err)
	}
	if key == nil {
		t.Error("NewECP256PrivateKey() returned nil key")
	}
}

// TestNewECP256PublicKey tests P-256 public key constructor validation
func TestNewECP256PublicKey(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "valid 64-byte key",
			input:     make([]byte, 64),
			wantError: false,
		},
		{
			name:      "invalid size - too small",
			input:     make([]byte, 63),
			wantError: true,
		},
		{
			name:      "invalid size - too large",
			input:     make([]byte, 65),
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewECP256PublicKey(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("NewECP256PublicKey() error = %v, wantError %v", err, tt.wantError)
			}
			if err == nil && key == nil {
				t.Error("NewECP256PublicKey() returned nil key without error")
			}
		})
	}
}

// TestNewECP384PrivateKey tests P-384 private key constructor validation
func TestNewECP384PrivateKey(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "valid 48-byte key",
			input:     make([]byte, 48),
			wantError: true, // all zeros is invalid
		},
		{
			name:      "invalid size - too small",
			input:     make([]byte, 47),
			wantError: true,
		},
		{
			name:      "invalid size - too large",
			input:     make([]byte, 49),
			wantError: true,
		},
		{
			name:      "empty input",
			input:     []byte{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewECP384PrivateKey(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("NewECP384PrivateKey() error = %v, wantError %v", err, tt.wantError)
			}
			if err == nil && key == nil {
				t.Error("NewECP384PrivateKey() returned nil key without error")
			}
		})
	}
}

// TestNewECP384PublicKey tests P-384 public key constructor validation
func TestNewECP384PublicKey(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "valid 96-byte key",
			input:     make([]byte, 96),
			wantError: false,
		},
		{
			name:      "invalid size - too small",
			input:     make([]byte, 95),
			wantError: true,
		},
		{
			name:      "invalid size - too large",
			input:     make([]byte, 97),
			wantError: true,
		},
		{
			name:      "empty input",
			input:     []byte{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewECP384PublicKey(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("NewECP384PublicKey() error = %v, wantError %v", err, tt.wantError)
			}
			if err == nil && key == nil {
				t.Error("NewECP384PublicKey() returned nil key without error")
			}
		})
	}
}

// TestNewECP521PrivateKey tests P-521 private key constructor validation
func TestNewECP521PrivateKey(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "valid 66-byte key",
			input:     make([]byte, 66),
			wantError: true, // all zeros is invalid
		},
		{
			name:      "invalid size - too small",
			input:     make([]byte, 65),
			wantError: true,
		},
		{
			name:      "invalid size - too large",
			input:     make([]byte, 67),
			wantError: true,
		},
		{
			name:      "empty input",
			input:     []byte{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewECP521PrivateKey(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("NewECP521PrivateKey() error = %v, wantError %v", err, tt.wantError)
			}
			if err == nil && key == nil {
				t.Error("NewECP521PrivateKey() returned nil key without error")
			}
		})
	}
}

// TestNewECP521PublicKey tests P-521 public key constructor validation
func TestNewECP521PublicKey(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "valid 132-byte key",
			input:     make([]byte, 132),
			wantError: false,
		},
		{
			name:      "invalid size - too small",
			input:     make([]byte, 131),
			wantError: true,
		},
		{
			name:      "invalid size - too large",
			input:     make([]byte, 133),
			wantError: true,
		},
		{
			name:      "empty input",
			input:     []byte{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewECP521PublicKey(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("NewECP521PublicKey() error = %v, wantError %v", err, tt.wantError)
			}
			if err == nil && key == nil {
				t.Error("NewECP521PublicKey() returned nil key without error")
			}
		})
	}
}

// TestECDSAKeyPairConsistencyP256 tests P-256 key generation and constructor round-trip
func TestECDSAKeyPairConsistencyP256(t *testing.T) {
	// Generate a real P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-256 key: %v", err)
	}

	// Get private key bytes
	privBytes := privKey.D.Bytes()
	if len(privBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privBytes):], privBytes)
		privBytes = padded
	}

	// Create our private key type
	ourPrivKey, err := NewECP256PrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewECP256PrivateKey() failed: %v", err)
	}

	// Get public key bytes (uncompressed X||Y)
	pubBytes := make([]byte, 64)
	privKey.PublicKey.X.FillBytes(pubBytes[0:32])
	privKey.PublicKey.Y.FillBytes(pubBytes[32:64])

	// Create our public key type
	ourPubKey, err := NewECP256PublicKey(pubBytes)
	if err != nil {
		t.Fatalf("NewECP256PublicKey() failed: %v", err)
	}

	// Verify keys are not nil
	if ourPrivKey == nil || ourPubKey == nil {
		t.Error("Constructed keys should not be nil")
	}
}

// TestECDSAConstructorDefensiveCopy verifies constructors return copies
func TestECDSAConstructorDefensiveCopy(t *testing.T) {
	t.Run("P-256 private key", func(t *testing.T) {
		original := make([]byte, 32)
		original[0] = 1 // Non-zero to pass validation

		key, err := NewECP256PrivateKey(original)
		if err != nil {
			t.Fatalf("Constructor failed: %v", err)
		}

		// Modify original
		original[0] = 99

		// Key should be unchanged
		if key[0] != 1 {
			t.Error("Constructor did not create defensive copy")
		}
	})

	t.Run("P-256 public key", func(t *testing.T) {
		original := make([]byte, 64)
		original[0] = 1

		key, err := NewECP256PublicKey(original)
		if err != nil {
			t.Fatalf("Constructor failed: %v", err)
		}

		// Modify original
		original[0] = 99

		// Key should be unchanged
		if key[0] != 1 {
			t.Error("Constructor did not create defensive copy")
		}
	})
}

// Benchmark constructors
func BenchmarkNewECP256PrivateKey(b *testing.B) {
	validKey := make([]byte, 32)
	validKey[0] = 1 // Non-zero

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewECP256PrivateKey(validKey)
	}
}

func BenchmarkNewECP256PublicKey(b *testing.B) {
	validKey := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewECP256PublicKey(validKey)
	}
}

func BenchmarkNewECP384PrivateKey(b *testing.B) {
	validKey := make([]byte, 48)
	validKey[0] = 1 // Non-zero

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewECP384PrivateKey(validKey)
	}
}

func BenchmarkNewECP384PublicKey(b *testing.B) {
	validKey := make([]byte, 96)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewECP384PublicKey(validKey)
	}
}

func BenchmarkNewECP521PrivateKey(b *testing.B) {
	validKey := make([]byte, 66)
	validKey[0] = 1 // Non-zero

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewECP521PrivateKey(validKey)
	}
}

func BenchmarkNewECP521PublicKey(b *testing.B) {
	validKey := make([]byte, 132)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewECP521PublicKey(validKey)
	}
}
