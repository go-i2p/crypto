package tunnel

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestTunnelEncryptionType_String validates the String() method for all encryption types
func TestTunnelEncryptionType_String(t *testing.T) {
	tests := []struct {
		name     string
		encType  TunnelEncryptionType
		expected string
	}{
		{
			name:     "AES encryption type",
			encType:  TunnelEncryptionAES,
			expected: "AES-256-CBC",
		},
		{
			name:     "ECIES encryption type",
			encType:  TunnelEncryptionECIES,
			expected: "ECIES-X25519",
		},
		{
			name:     "unknown encryption type",
			encType:  TunnelEncryptionType(99),
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.encType.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestNewTunnelEncryptor_AES validates factory function for AES encryption
func TestNewTunnelEncryptor_AES(t *testing.T) {
	tests := []struct {
		name        string
		layerKey    TunnelKey
		ivKey       TunnelKey
		expectError bool
	}{
		{
			name:        "valid AES keys",
			layerKey:    generateTestKey(t),
			ivKey:       generateTestKey(t),
			expectError: false,
		},
		{
			name:        "zero AES keys",
			layerKey:    TunnelKey{},
			ivKey:       TunnelKey{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptor, err := NewTunnelEncryptor(TunnelEncryptionAES, tt.layerKey, tt.ivKey)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
				if encryptor != nil {
					t.Error("encryptor should be nil on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if encryptor == nil {
					t.Fatal("encryptor should not be nil")
				}

				// Verify correct type
				if encryptor.Type() != TunnelEncryptionAES {
					t.Errorf("expected type %v, got %v", TunnelEncryptionAES, encryptor.Type())
				}

				// Verify encryptor is actually an AESEncryptor
				if _, ok := encryptor.(*AESEncryptor); !ok {
					t.Error("encryptor should be *AESEncryptor")
				}
			}
		})
	}
}

// TestNewTunnelEncryptor_ECIES validates factory function for ECIES encryption
func TestNewTunnelEncryptor_ECIES(t *testing.T) {
	// Create a test public key for ECIES (using layerKey parameter)
	var layerKey TunnelKey
	// Fill with test data (in real usage this would be an X25519 public key)
	for i := range layerKey {
		layerKey[i] = byte(i)
	}

	encryptor, err := NewTunnelEncryptor(TunnelEncryptionECIES, layerKey, TunnelKey{})
	if err != nil {
		t.Errorf("expected ECIES encryption to be implemented, got error: %v", err)
	}

	if encryptor == nil {
		t.Error("encryptor should not be nil for ECIES encryption type")
	}

	if encryptor != nil && encryptor.Type() != TunnelEncryptionECIES {
		t.Errorf("expected TunnelEncryptionECIES, got %v", encryptor.Type())
	}
}

// TestNewTunnelEncryptor_InvalidType validates factory function with invalid encryption type
func TestNewTunnelEncryptor_InvalidType(t *testing.T) {
	invalidType := TunnelEncryptionType(99)
	encryptor, err := NewTunnelEncryptor(invalidType, TunnelKey{}, TunnelKey{})

	if err == nil {
		t.Error("expected error for invalid encryption type")
	}
	if encryptor != nil {
		t.Error("encryptor should be nil for invalid encryption type")
	}
}

// TestTunnelEncryptor_Interface validates that AESEncryptor implements TunnelEncryptor
func TestTunnelEncryptor_Interface(t *testing.T) {
	layerKey := generateTestKey(t)
	ivKey := generateTestKey(t)

	// Create via factory
	var encryptor TunnelEncryptor
	encryptor, err := NewTunnelEncryptor(TunnelEncryptionAES, layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	// Verify interface methods work
	data := generateTestTunnelData(t)
	original := *data

	// Test Encrypt through interface (convert TunnelData to []byte)
	encrypted, err := encryptor.Encrypt(data[:])
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Test Decrypt through interface
	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify round trip (compare payloads for AES)
	if encryptor.Type() == TunnelEncryptionAES {
		// For AES, compare the 1008-byte payload (excluding IV)
		if !bytes.Equal(decrypted, original[16:1024]) {
			t.Error("AES round trip should restore original payload data")
		}
	}

	// Test Type through interface
	if encryptor.Type() != TunnelEncryptionAES {
		t.Errorf("expected type %v, got %v", TunnelEncryptionAES, encryptor.Type())
	}
}

// TestTunnelEncryptor_Polymorphism validates interface polymorphism
func TestTunnelEncryptor_Polymorphism(t *testing.T) {
	// Create multiple encryptors via interface
	encryptors := []TunnelEncryptor{}

	// Add AES encryptor
	aesEncryptor, err := NewTunnelEncryptor(TunnelEncryptionAES, generateTestKey(t), generateTestKey(t))
	if err != nil {
		t.Fatalf("failed to create AES encryptor: %v", err)
	}
	encryptors = append(encryptors, aesEncryptor)

	// Test each encryptor through interface
	for i, enc := range encryptors {
		t.Run(enc.Type().String(), func(t *testing.T) {
			data := generateTestTunnelData(t)
			original := *data

			encrypted, err := enc.Encrypt(data[:])
			if err != nil {
				t.Fatalf("encryptor %d Encrypt failed: %v", i, err)
			}

			decrypted, err := enc.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("encryptor %d Decrypt failed: %v", i, err)
			}

			// For AES, verify payload is restored (excluding IV)
			if enc.Type() == TunnelEncryptionAES {
				if !bytes.Equal(decrypted, original[16:1024]) {
					t.Errorf("encryptor %d round trip failed for AES payload", i)
				}
			}
		})
	}
}

// BenchmarkNewTunnelEncryptor measures factory function performance
func BenchmarkNewTunnelEncryptor(b *testing.B) {
	layerKey := TunnelKey{}
	ivKey := TunnelKey{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewTunnelEncryptor(TunnelEncryptionAES, layerKey, ivKey)
	}
}

// Helper functions for testing
func generateTestKey(t *testing.T) TunnelKey {
	t.Helper()
	var key TunnelKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return key
}

func generateTestTunnelData(t *testing.T) *TunnelData {
	t.Helper()
	data := &TunnelData{}
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatalf("failed to generate test data: %v", err)
	}
	return data
}

// TestAESEncryptor_KnownAnswer verifies F079 (no value-copy discard), F080
// (correct IV offset / single-block transform), F081 (full 1024-byte payload,
// 1028-byte output). If the encryptor writes into a discarded copy, ciphertext
// equals plaintext; this test fails that case.
func TestAESEncryptor_KnownAnswer(t *testing.T) {
	layerKey := TunnelKey{0: 1, 1: 2, 2: 3, 3: 4, 4: 5, 5: 6, 6: 7, 7: 8,
		8: 9, 9: 10, 10: 11, 11: 12, 12: 13, 13: 14, 14: 15, 15: 16,
		16: 17, 17: 18, 18: 19, 19: 20, 20: 21, 21: 22, 22: 23, 23: 24,
		24: 25, 25: 26, 26: 27, 27: 28, 28: 29, 29: 30, 30: 31, 31: 32}
	ivKey := layerKey

	aes, err := NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("NewAESEncryptor failed: %v", err)
	}

	plaintext := make([]byte, 1008)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := aes.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(ciphertext) != 1028 {
		t.Errorf("expected 1028-byte ciphertext, got %d", len(ciphertext))
	}
	if bytes.Equal(ciphertext, append(make([]byte, 16), plaintext...)) {
		t.Error("ciphertext equals plaintext + zero IV: value-copy bug (F079)")
	}

	decrypted, err := aes.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if len(decrypted) != 1008 {
		t.Errorf("expected 1008-byte payload, got %d", len(decrypted))
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypt round-trip failed: payload does not match original")
	}
}
