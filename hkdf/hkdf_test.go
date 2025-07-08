package hkdf

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

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
