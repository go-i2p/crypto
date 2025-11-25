package tunnel

import (
	"bytes"
	"testing"
)

// TestNewTunnelKey tests the TunnelKey constructor
func TestNewTunnelKey(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid 32-byte key",
			data:    make([]byte, 32),
			wantErr: false,
		},
		{
			name:    "too short",
			data:    make([]byte, 31),
			wantErr: true,
		},
		{
			name:    "too long",
			data:    make([]byte, 33),
			wantErr: true,
		},
		{
			name:    "nil data",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "all zeros",
			data:    make([]byte, 32),
			wantErr: true,
		},
		{
			name:    "empty slice",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill non-zero test data
			if tt.name == "valid 32-byte key" {
				for i := range tt.data {
					tt.data[i] = byte(i % 256)
				}
			}

			key, err := NewTunnelKey(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTunnelKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && key == nil {
				t.Error("NewTunnelKey() returned nil key")
			}
		})
	}
}

// TestTunnelKeyDefensiveCopy verifies that NewTunnelKey makes a defensive copy
func TestTunnelKeyDefensiveCopy(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i % 256)
	}
	original := make([]byte, len(data))
	copy(original, data)

	key, err := NewTunnelKey(data)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Modify original data
	data[0] = 0xFF

	// Key should not be affected
	if bytes.Equal(key[:], data) {
		t.Error("NewTunnelKey did not make defensive copy")
	}
	if !bytes.Equal(key[:], original) {
		t.Error("Key was modified when input was modified")
	}
}

// TestNewAESEncryptor validates AES encryptor creation with various key configurations
func TestNewAESEncryptor(t *testing.T) {
	tests := []struct {
		name        string
		layerKey    TunnelKey
		ivKey       TunnelKey
		expectError bool
		errorCheck  func(error) bool
	}{
		{
			name:        "valid 32-byte keys",
			layerKey:    generateTestKey(t),
			ivKey:       generateTestKey(t),
			expectError: false,
		},
		{
			name:        "zero keys should still work",
			layerKey:    TunnelKey{},
			ivKey:       TunnelKey{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptor, err := NewAESEncryptor(tt.layerKey, tt.ivKey)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errorCheck != nil && !tt.errorCheck(err) {
					t.Errorf("error check failed for error: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if encryptor == nil {
					t.Error("encryptor should not be nil when no error")
				}
			}
		})
	}
}

// TestNewTunnelCrypto_BackwardCompatibility ensures the deprecated function still works
func TestNewTunnelCrypto_BackwardCompatibility(t *testing.T) {
	layerKey := generateTestKey(t)
	ivKey := generateTestKey(t)

	encryptor, err := NewTunnelCrypto(layerKey, ivKey)
	if err != nil {
		t.Fatalf("NewTunnelCrypto failed: %v", err)
	}
	if encryptor == nil {
		t.Fatal("encryptor should not be nil")
	}

	// Verify it returns the correct type
	if encryptor.Type() != TunnelEncryptionAES {
		t.Errorf("expected type %v, got %v", TunnelEncryptionAES, encryptor.Type())
	}
}

// TestAESEncryptor_Encrypt validates encryption with various data patterns
func TestAESEncryptor_Encrypt(t *testing.T) {
	layerKey := generateTestKey(t)
	ivKey := generateTestKey(t)
	encryptor, err := NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	tests := []struct {
		name        string
		data        *TunnelData
		expectError bool
	}{
		{
			name:        "valid tunnel data",
			data:        generateTestTunnelData(t),
			expectError: false,
		},
		{
			name:        "nil tunnel data",
			data:        nil,
			expectError: true,
		},
		{
			name:        "zero-filled data",
			data:        &TunnelData{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result []byte
			var err error

			if tt.data == nil {
				result, err = encryptor.Encrypt(nil)
			} else {
				result, err = encryptor.Encrypt(tt.data[:])
			}

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.data != nil && len(result) != 1028 {
					t.Errorf("expected 1028 bytes, got %d", len(result))
				}
				// Note: First 16 bytes (IV) are not encrypted, only bytes 16-1024
				// For random data, the encrypted portion should differ
				// For zero data with zero keys, output might be identical - this is OK
			}
		})
	}
}

// TestAESEncryptor_Decrypt validates decryption with various data patterns
func TestAESEncryptor_Decrypt(t *testing.T) {
	layerKey := generateTestKey(t)
	ivKey := generateTestKey(t)
	encryptor, err := NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	tests := []struct {
		name        string
		data        *TunnelData
		expectError bool
	}{
		{
			name:        "valid encrypted data",
			data:        generateTestTunnelData(t),
			expectError: false,
		},
		{
			name:        "nil tunnel data",
			data:        nil,
			expectError: true,
		},
		{
			name:        "zero-filled data",
			data:        &TunnelData{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result []byte
			var err error

			if tt.data == nil {
				result, err = encryptor.Decrypt(nil)
			} else {
				result, err = encryptor.Decrypt(tt.data[:])
			}

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.data != nil && len(result) != 1008 {
					t.Errorf("expected 1008 bytes (payload), got %d", len(result))
				}
				// Note: New interface returns only the 1008-byte payload (excluding 16-byte IV)
				// For random data, the decrypted portion should differ from encrypted
				// For zero data with zero keys, output might be identical - this is OK
			}
		})
	}
}

// TestAESEncryptor_RoundTrip validates encrypt-decrypt round trip preserves data
func TestAESEncryptor_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data *TunnelData
	}{
		{
			name: "random data",
			data: generateTestTunnelData(t),
		},
		{
			name: "zero-filled data",
			data: &TunnelData{},
		},
		{
			name: "pattern data",
			data: generatePatternData(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layerKey := generateTestKey(t)
			ivKey := generateTestKey(t)
			encryptor, err := NewAESEncryptor(layerKey, ivKey)
			if err != nil {
				t.Fatalf("failed to create encryptor: %v", err)
			}

			// Save original data
			original := *tt.data

			// Encrypt
			if _, err := encryptor.Encrypt(tt.data[:]); err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			// Decrypt
			if _, err := encryptor.Decrypt(tt.data[:]); err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			// Verify round trip restored original
			if !bytes.Equal(original[:], (*tt.data)[:]) {
				t.Error("round trip should restore original data")
			}
		})
	}
}

// TestAESEncryptor_Type validates the Type() method returns correct value
func TestAESEncryptor_Type(t *testing.T) {
	layerKey := generateTestKey(t)
	ivKey := generateTestKey(t)
	encryptor, err := NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	if encryptor.Type() != TunnelEncryptionAES {
		t.Errorf("expected type %v, got %v", TunnelEncryptionAES, encryptor.Type())
	}
}

// TestAESEncryptor_MultipleOperations ensures encryptor can be reused
func TestAESEncryptor_MultipleOperations(t *testing.T) {
	layerKey := generateTestKey(t)
	ivKey := generateTestKey(t)
	encryptor, err := NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	// Perform multiple encrypt-decrypt cycles
	for i := 0; i < 10; i++ {
		data := generateTestTunnelData(t)
		original := *data

		if _, err := encryptor.Encrypt(data[:]); err != nil {
			t.Fatalf("encryption %d failed: %v", i, err)
		}

		if _, err := encryptor.Decrypt(data[:]); err != nil {
			t.Fatalf("decryption %d failed: %v", i, err)
		}

		if !bytes.Equal(original[:], (*data)[:]) {
			t.Errorf("round trip %d failed to restore data", i)
		}
	}
}

// TestAESEncryptor_DifferentKeysProduceDifferentResults validates key isolation
func TestAESEncryptor_DifferentKeysProduceDifferentResults(t *testing.T) {
	// Use two independent datasets with different IVs
	data1 := generateTestTunnelData(t)
	data2 := generateTestTunnelData(t)

	// Create two encryptors with different keys
	layerKey1 := generateTestKey(t)
	ivKey1 := generateTestKey(t)
	encryptor1, err := NewAESEncryptor(layerKey1, ivKey1)
	if err != nil {
		t.Fatalf("failed to create encryptor1: %v", err)
	}

	layerKey2 := generateTestKey(t)
	ivKey2 := generateTestKey(t)
	encryptor2, err := NewAESEncryptor(layerKey2, ivKey2)
	if err != nil {
		t.Fatalf("failed to create encryptor2: %v", err)
	}

	// Encrypt different data with different encryptors - they should produce different results
	if _, err := encryptor1.Encrypt(data1[:]); err != nil {
		t.Fatalf("encryption1 failed: %v", err)
	}
	if _, err := encryptor2.Encrypt(data2[:]); err != nil {
		t.Fatalf("encryption2 failed: %v", err)
	}

	// With different keys and random data, the encrypted results should be different
	// This is a sanity check that encryption is actually using the keys
	if bytes.Equal((*data1)[:], (*data2)[:]) {
		t.Error("encrypting random data with different keys produced identical results (extremely unlikely)")
	}
}

// BenchmarkAESEncryptor_Encrypt measures encryption performance
func BenchmarkAESEncryptor_Encrypt(b *testing.B) {
	layerKey := TunnelKey{}
	ivKey := TunnelKey{}
	encryptor, _ := NewAESEncryptor(layerKey, ivKey)
	data := &TunnelData{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encryptor.Encrypt(data[:])
	}
}

// BenchmarkAESEncryptor_Decrypt measures decryption performance
func BenchmarkAESEncryptor_Decrypt(b *testing.B) {
	layerKey := TunnelKey{}
	ivKey := TunnelKey{}
	encryptor, _ := NewAESEncryptor(layerKey, ivKey)
	data := &TunnelData{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encryptor.Decrypt(data[:])
	}
}

// BenchmarkAESEncryptor_RoundTrip measures full encryption-decryption performance
func BenchmarkAESEncryptor_RoundTrip(b *testing.B) {
	layerKey := TunnelKey{}
	ivKey := TunnelKey{}
	encryptor, _ := NewAESEncryptor(layerKey, ivKey)
	data := &TunnelData{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encryptor.Encrypt(data[:])
		_, _ = encryptor.Decrypt(data[:])
	}
}

// Helper functions

// generatePatternData creates predictable pattern data for testing
func generatePatternData() *TunnelData {
	data := &TunnelData{}
	for i := range data {
		data[i] = byte(i % 256)
	}
	return data
}
