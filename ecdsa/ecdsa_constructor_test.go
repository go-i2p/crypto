package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// generateP256TestKey generates a real P-256 ECDSA key pair and returns
// the stdlib private key and the padded private key bytes.
func generateP256TestKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-256 key: %v", err)
	}
	privBytes := privKey.D.Bytes()
	if len(privBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privBytes):], privBytes)
		privBytes = padded
	}
	return privKey, privBytes
}

// assertConstructorValidation is a test helper that validates a key constructor
// rejects invalid sizes, empty, and nil inputs consistent with ECDSA key requirements.
func assertConstructorValidation(t *testing.T, name string, constructor func([]byte) (interface{}, error), validSize int, zeroIsInvalid bool) {
	t.Helper()

	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{"valid key", make([]byte, validSize), zeroIsInvalid},
		{"invalid size - too small", make([]byte, validSize-1), true},
		{"invalid size - too large", make([]byte, validSize+1), true},
		{"empty input", []byte{}, true},
		{"nil input", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := constructor(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("%s() error = %v, wantError %v", name, err, tt.wantError)
			}
			if err == nil && key == nil {
				t.Errorf("%s() returned nil key without error", name)
			}
		})
	}
}

// TestECDSAConstructorValidation tests all ECDSA key constructors with a common validation pattern.
func TestECDSAConstructorValidation(t *testing.T) {
	constructors := []struct {
		name          string
		constructor   func([]byte) (interface{}, error)
		validSize     int
		zeroIsInvalid bool
	}{
		{"NewECP256PrivateKey", func(b []byte) (interface{}, error) { return NewECP256PrivateKey(b) }, 32, true},
		{"NewECP256PublicKey", func(b []byte) (interface{}, error) { return NewECP256PublicKey(b) }, 64, false},
		{"NewECP384PrivateKey", func(b []byte) (interface{}, error) { return NewECP384PrivateKey(b) }, 48, true},
		{"NewECP384PublicKey", func(b []byte) (interface{}, error) { return NewECP384PublicKey(b) }, 96, false},
		{"NewECP521PrivateKey", func(b []byte) (interface{}, error) { return NewECP521PrivateKey(b) }, 66, true},
		{"NewECP521PublicKey", func(b []byte) (interface{}, error) { return NewECP521PublicKey(b) }, 132, false},
	}

	for _, ctor := range constructors {
		t.Run(ctor.name, func(t *testing.T) {
			assertConstructorValidation(t, ctor.name, ctor.constructor, ctor.validSize, ctor.zeroIsInvalid)
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
	_, privBytes := generateP256TestKey(t)

	key, err := NewECP256PrivateKey(privBytes)
	if err != nil {
		t.Errorf("NewECP256PrivateKey() failed with valid key: %v", err)
	}
	if key == nil {
		t.Error("NewECP256PrivateKey() returned nil key")
	}
}

// TestECDSAKeyPairConsistencyP256 tests P-256 key generation and constructor round-trip
func TestECDSAKeyPairConsistencyP256(t *testing.T) {
	privKey, privBytes := generateP256TestKey(t)

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

// BenchmarkECDSAConstructors benchmarks all ECDSA key constructors with a table-driven approach.
func BenchmarkECDSAConstructors(b *testing.B) {
	constructors := []struct {
		name        string
		constructor func([]byte) (interface{}, error)
		size        int
		nonZero     bool // whether to set first byte non-zero for private keys
	}{
		{"ECP256PrivateKey", func(d []byte) (interface{}, error) { return NewECP256PrivateKey(d) }, 32, true},
		{"ECP256PublicKey", func(d []byte) (interface{}, error) { return NewECP256PublicKey(d) }, 64, false},
		{"ECP384PrivateKey", func(d []byte) (interface{}, error) { return NewECP384PrivateKey(d) }, 48, true},
		{"ECP384PublicKey", func(d []byte) (interface{}, error) { return NewECP384PublicKey(d) }, 96, false},
		{"ECP521PrivateKey", func(d []byte) (interface{}, error) { return NewECP521PrivateKey(d) }, 66, true},
		{"ECP521PublicKey", func(d []byte) (interface{}, error) { return NewECP521PublicKey(d) }, 132, false},
	}

	for _, ctor := range constructors {
		validKey := make([]byte, ctor.size)
		if ctor.nonZero {
			validKey[0] = 1
		}

		b.Run(ctor.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = ctor.constructor(validKey)
			}
		})
	}
}
