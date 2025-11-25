package aes

import (
	"crypto/rand"
	"testing"
)

// TestNewAESKey tests the general AES key constructor with various key sizes
func TestNewAESKey(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		ivSize    int
		wantError bool
	}{
		{
			name:      "valid AES-128 (16-byte key)",
			keySize:   16,
			ivSize:    16,
			wantError: false,
		},
		{
			name:      "valid AES-192 (24-byte key)",
			keySize:   24,
			ivSize:    16,
			wantError: false,
		},
		{
			name:      "valid AES-256 (32-byte key)",
			keySize:   32,
			ivSize:    16,
			wantError: false,
		},
		{
			name:      "invalid key size - too small",
			keySize:   15,
			ivSize:    16,
			wantError: true,
		},
		{
			name:      "invalid key size - between valid sizes",
			keySize:   20,
			ivSize:    16,
			wantError: true,
		},
		{
			name:      "invalid key size - too large",
			keySize:   48,
			ivSize:    16,
			wantError: true,
		},
		{
			name:      "invalid IV size - too small",
			keySize:   32,
			ivSize:    8,
			wantError: true,
		},
		{
			name:      "invalid IV size - too large",
			keySize:   32,
			ivSize:    32,
			wantError: true,
		},
		{
			name:      "zero key size",
			keySize:   0,
			ivSize:    16,
			wantError: true,
		},
		{
			name:      "zero IV size",
			keySize:   32,
			ivSize:    0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			iv := make([]byte, tt.ivSize)

			aesKey, err := NewAESKey(key, iv)
			if (err != nil) != tt.wantError {
				t.Errorf("NewAESKey() error = %v, wantError %v", err, tt.wantError)
			}
			if err == nil && aesKey == nil {
				t.Error("NewAESKey() returned nil key without error")
			}
			if err == nil {
				if len(aesKey.Key) != tt.keySize {
					t.Errorf("Key length = %d, want %d", len(aesKey.Key), tt.keySize)
				}
				if len(aesKey.IV) != tt.ivSize {
					t.Errorf("IV length = %d, want %d", len(aesKey.IV), tt.ivSize)
				}
			}
		})
	}
}

// TestNewAES256Key tests the AES-256 specific constructor
func TestNewAES256Key(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		key := make([]byte, 32)
		iv := make([]byte, 16)
		rand.Read(key)
		rand.Read(iv)

		aesKey, err := NewAES256Key(key, iv)
		if err != nil {
			t.Errorf("NewAES256Key() failed with valid input: %v", err)
		}
		if aesKey == nil {
			t.Error("NewAES256Key() returned nil key")
		}
		if len(aesKey.Key) != 32 {
			t.Errorf("Key length = %d, want 32", len(aesKey.Key))
		}
	})

	t.Run("invalid key size - too small", func(t *testing.T) {
		key := make([]byte, 24)
		iv := make([]byte, 16)

		_, err := NewAES256Key(key, iv)
		if err == nil {
			t.Error("NewAES256Key() should reject 24-byte key")
		}
	})

	t.Run("invalid key size - too large", func(t *testing.T) {
		key := make([]byte, 48)
		iv := make([]byte, 16)

		_, err := NewAES256Key(key, iv)
		if err == nil {
			t.Error("NewAES256Key() should reject 48-byte key")
		}
	})

	t.Run("invalid IV size", func(t *testing.T) {
		key := make([]byte, 32)
		iv := make([]byte, 8)

		_, err := NewAES256Key(key, iv)
		if err == nil {
			t.Error("NewAES256Key() should reject 8-byte IV")
		}
	})
}

// TestNewAES192Key tests the AES-192 specific constructor
func TestNewAES192Key(t *testing.T) {
	t.Run("valid 24-byte key", func(t *testing.T) {
		key := make([]byte, 24)
		iv := make([]byte, 16)
		rand.Read(key)
		rand.Read(iv)

		aesKey, err := NewAES192Key(key, iv)
		if err != nil {
			t.Errorf("NewAES192Key() failed with valid input: %v", err)
		}
		if aesKey == nil {
			t.Error("NewAES192Key() returned nil key")
		}
		if len(aesKey.Key) != 24 {
			t.Errorf("Key length = %d, want 24", len(aesKey.Key))
		}
	})

	t.Run("invalid key size", func(t *testing.T) {
		key := make([]byte, 32)
		iv := make([]byte, 16)

		_, err := NewAES192Key(key, iv)
		if err == nil {
			t.Error("NewAES192Key() should reject 32-byte key")
		}
	})
}

// TestNewAES128Key tests the AES-128 specific constructor
func TestNewAES128Key(t *testing.T) {
	t.Run("valid 16-byte key", func(t *testing.T) {
		key := make([]byte, 16)
		iv := make([]byte, 16)
		rand.Read(key)
		rand.Read(iv)

		aesKey, err := NewAES128Key(key, iv)
		if err != nil {
			t.Errorf("NewAES128Key() failed with valid input: %v", err)
		}
		if aesKey == nil {
			t.Error("NewAES128Key() returned nil key")
		}
		if len(aesKey.Key) != 16 {
			t.Errorf("Key length = %d, want 16", len(aesKey.Key))
		}
	})

	t.Run("invalid key size", func(t *testing.T) {
		key := make([]byte, 24)
		iv := make([]byte, 16)

		_, err := NewAES128Key(key, iv)
		if err == nil {
			t.Error("NewAES128Key() should reject 24-byte key")
		}
	})
}

// TestAESKeyDefensiveCopy verifies constructors return defensive copies
func TestAESKeyDefensiveCopy(t *testing.T) {
	t.Run("key mutation does not affect AESSymmetricKey", func(t *testing.T) {
		originalKey := make([]byte, 32)
		originalIV := make([]byte, 16)
		originalKey[0] = 1
		originalIV[0] = 2

		aesKey, err := NewAESKey(originalKey, originalIV)
		if err != nil {
			t.Fatalf("Constructor failed: %v", err)
		}

		// Modify original slices
		originalKey[0] = 99
		originalIV[0] = 88

		// AESSymmetricKey should be unchanged
		if aesKey.Key[0] != 1 {
			t.Error("Constructor did not create defensive copy of key")
		}
		if aesKey.IV[0] != 2 {
			t.Error("Constructor did not create defensive copy of IV")
		}
	})
}

// TestAESKeyEncrypterDecrypter tests that keys work with encrypter/decrypter
func TestAESKeyEncrypterDecrypter(t *testing.T) {
	t.Run("AES-256 encrypt/decrypt round-trip", func(t *testing.T) {
		key := make([]byte, 32)
		iv := make([]byte, 16)
		rand.Read(key)
		rand.Read(iv)

		aesKey, err := NewAES256Key(key, iv)
		if err != nil {
			t.Fatalf("NewAES256Key() failed: %v", err)
		}

		// Test NewEncrypter
		encrypter, err := aesKey.NewEncrypter()
		if err != nil {
			t.Errorf("NewEncrypter() failed: %v", err)
		}
		if encrypter == nil {
			t.Error("NewEncrypter() returned nil")
		}

		// Test NewDecrypter
		decrypter, err := aesKey.NewDecrypter()
		if err != nil {
			t.Errorf("NewDecrypter() failed: %v", err)
		}
		if decrypter == nil {
			t.Error("NewDecrypter() returned nil")
		}
	})

	t.Run("AES-128 encrypt/decrypt", func(t *testing.T) {
		key := make([]byte, 16)
		iv := make([]byte, 16)
		rand.Read(key)
		rand.Read(iv)

		aesKey, err := NewAES128Key(key, iv)
		if err != nil {
			t.Fatalf("NewAES128Key() failed: %v", err)
		}

		encrypter, err := aesKey.NewEncrypter()
		if err != nil {
			t.Errorf("NewEncrypter() failed: %v", err)
		}
		if encrypter == nil {
			t.Error("NewEncrypter() returned nil")
		}
	})
}

// TestAESKeyZero tests the Zero method
func TestAESKeyZero(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(i + 100)
	}

	aesKey, err := NewAES256Key(key, iv)
	if err != nil {
		t.Fatalf("NewAES256Key() failed: %v", err)
	}

	// Verify key is not zero before Zero()
	isZero := true
	for _, b := range aesKey.Key {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		t.Error("Key should not be zero before Zero() is called")
	}

	// Call Zero()
	aesKey.Zero()

	// Verify key is zeroed
	for i, b := range aesKey.Key {
		if b != 0 {
			t.Errorf("Key byte %d = %d, want 0 after Zero()", i, b)
		}
	}

	// Verify IV is zeroed
	for i, b := range aesKey.IV {
		if b != 0 {
			t.Errorf("IV byte %d = %d, want 0 after Zero()", i, b)
		}
	}
}

// TestAESKeyLen tests the Len method
func TestAESKeyLen(t *testing.T) {
	tests := []struct {
		name        string
		keySize     int
		expectedLen int
	}{
		{"AES-128", 16, 16},
		{"AES-192", 24, 24},
		{"AES-256", 32, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			iv := make([]byte, 16)

			aesKey, err := NewAESKey(key, iv)
			if err != nil {
				t.Fatalf("NewAESKey() failed: %v", err)
			}

			if aesKey.Len() != tt.expectedLen {
				t.Errorf("Len() = %d, want %d", aesKey.Len(), tt.expectedLen)
			}
		})
	}
}

// Benchmark constructors
func BenchmarkNewAESKey(b *testing.B) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewAESKey(key, iv)
	}
}

func BenchmarkNewAES256Key(b *testing.B) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewAES256Key(key, iv)
	}
}

func BenchmarkNewAES128Key(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewAES128Key(key, iv)
	}
}
