package hkdf

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

// TestNewHKDF tests the default HKDF constructor
func TestNewHKDF(t *testing.T) {
	deriver := NewHKDF()
	if deriver == nil {
		t.Fatal("NewHKDF() returned nil")
	}

	// Test that it uses SHA-256 by default
	impl, ok := deriver.(*HKDFImpl)
	if !ok {
		t.Fatal("NewHKDF() did not return *HKDFImpl")
	}

	if impl.hashFunc == nil {
		t.Error("NewHKDF() created deriver with nil hashFunc")
	}

	// Verify it works
	ikm := []byte("test input")
	key, err := deriver.DeriveDefault(ikm)
	if err != nil {
		t.Fatalf("DeriveDefault failed: %v", err)
	}
	if len(key) != DefaultKeyLength {
		t.Errorf("Expected key length %d, got %d", DefaultKeyLength, len(key))
	}
}

// TestNewHKDFWithHash tests the custom hash function constructor
func TestNewHKDFWithHash(t *testing.T) {
	t.Run("valid hash function - SHA-256", func(t *testing.T) {
		deriver := NewHKDFWithHash(sha256.New)
		if deriver == nil {
			t.Fatal("NewHKDFWithHash() returned nil")
		}

		ikm := []byte("test input")
		key, err := deriver.DeriveDefault(ikm)
		if err != nil {
			t.Fatalf("DeriveDefault failed: %v", err)
		}
		if len(key) != DefaultKeyLength {
			t.Errorf("Expected key length %d, got %d", DefaultKeyLength, len(key))
		}
	})

	t.Run("valid hash function - SHA-512", func(t *testing.T) {
		deriver := NewHKDFWithHash(sha512.New)
		if deriver == nil {
			t.Fatal("NewHKDFWithHash() returned nil")
		}

		ikm := []byte("test input")
		key, err := deriver.DeriveDefault(ikm)
		if err != nil {
			t.Fatalf("DeriveDefault failed: %v", err)
		}
		if len(key) != DefaultKeyLength {
			t.Errorf("Expected key length %d, got %d", DefaultKeyLength, len(key))
		}
	})

	t.Run("nil hash function panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("NewHKDFWithHash(nil) should panic")
			}
		}()
		NewHKDFWithHash(nil)
	})
}

// TestHKDFHashFunctionDifference verifies different hash functions produce different outputs
func TestHKDFHashFunctionDifference(t *testing.T) {
	ikm := []byte("test input key material")
	salt := []byte("salt")
	info := []byte("context info")

	deriver256 := NewHKDFWithHash(sha256.New)
	deriver512 := NewHKDFWithHash(sha512.New)

	key256, err := deriver256.Derive(ikm, salt, info, 32)
	if err != nil {
		t.Fatalf("SHA-256 derivation failed: %v", err)
	}

	key512, err := deriver512.Derive(ikm, salt, info, 32)
	if err != nil {
		t.Fatalf("SHA-512 derivation failed: %v", err)
	}

	// Different hash functions should produce different keys
	if bytes.Equal(key256, key512) {
		t.Error("SHA-256 and SHA-512 should produce different keys")
	}
}

// TestHKDFDefaultVsCustomSHA256 verifies NewHKDF and NewHKDFWithHash(sha256.New) are equivalent
func TestHKDFDefaultVsCustomSHA256(t *testing.T) {
	ikm := []byte("test input key material")
	salt := []byte("salt")
	info := []byte("context info")

	deriverDefault := NewHKDF()
	deriverCustom := NewHKDFWithHash(sha256.New)

	keyDefault, err := deriverDefault.Derive(ikm, salt, info, 32)
	if err != nil {
		t.Fatalf("Default derivation failed: %v", err)
	}

	keyCustom, err := deriverCustom.Derive(ikm, salt, info, 32)
	if err != nil {
		t.Fatalf("Custom SHA-256 derivation failed: %v", err)
	}

	// Should produce identical results
	if !bytes.Equal(keyDefault, keyCustom) {
		t.Error("NewHKDF() and NewHKDFWithHash(sha256.New) should produce identical results")
	}
}

func TestHKDF_DeriveDefault(t *testing.T) {
	h := NewHKDF()

	// Test with known input
	ikm := []byte("test input key material")

	key, err := h.DeriveDefault(ikm)
	if err != nil {
		t.Fatalf("DeriveDefault failed: %v", err)
	}

	if len(key) != DefaultKeyLength {
		t.Errorf("Expected key length %d, got %d", DefaultKeyLength, len(key))
	}

	// Test consistency - same input should produce same output
	key2, err := h.DeriveDefault(ikm)
	if err != nil {
		t.Fatalf("DeriveDefault failed on second call: %v", err)
	}

	if !bytes.Equal(key, key2) {
		t.Error("HKDF should produce consistent results for same input")
	}
}

func TestHKDF_Derive(t *testing.T) {
	h := NewHKDF()

	tests := []struct {
		name    string
		ikm     []byte
		salt    []byte
		info    []byte
		keyLen  int
		wantErr bool
	}{
		{
			name:    "basic derivation",
			ikm:     []byte("input key material"),
			salt:    []byte("salt"),
			info:    []byte("context info"),
			keyLen:  32,
			wantErr: false,
		},
		{
			name:    "no salt",
			ikm:     []byte("input key material"),
			salt:    nil,
			info:    []byte("context info"),
			keyLen:  16,
			wantErr: false,
		},
		{
			name:    "no info",
			ikm:     []byte("input key material"),
			salt:    []byte("salt"),
			info:    nil,
			keyLen:  64,
			wantErr: false,
		},
		{
			name:    "invalid key length",
			ikm:     []byte("input key material"),
			salt:    []byte("salt"),
			info:    []byte("context info"),
			keyLen:  0,
			wantErr: true,
		},
		{
			name:    "negative key length",
			ikm:     []byte("input key material"),
			salt:    []byte("salt"),
			info:    []byte("context info"),
			keyLen:  -1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := h.Derive(tt.ikm, tt.salt, tt.info, tt.keyLen)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(key) != tt.keyLen {
				t.Errorf("Expected key length %d, got %d", tt.keyLen, len(key))
			}
		})
	}
}

func TestHKDF_WithCustomHash(t *testing.T) {
	h := NewHKDFWithHash(sha256.New)

	ikm := []byte("test input")
	key, err := h.DeriveDefault(ikm)
	if err != nil {
		t.Fatalf("DeriveDefault with custom hash failed: %v", err)
	}

	if len(key) != DefaultKeyLength {
		t.Errorf("Expected key length %d, got %d", DefaultKeyLength, len(key))
	}
}

func TestHKDF_InfoTooLong(t *testing.T) {
	h := NewHKDF()

	ikm := []byte("input key material")
	salt := []byte("salt")
	info := make([]byte, MaxInfoLength+1) // Exceed maximum

	_, err := h.Derive(ikm, salt, info, 32)
	if err == nil {
		t.Error("Expected error for info too long")
	}
}
