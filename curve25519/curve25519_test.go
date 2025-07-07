package curve25519

import (
	"crypto/rand"
	"testing"

	curve25519 "go.step.sm/crypto/x25519"
)

func TestCurve25519EncryptionDataSize(t *testing.T) {
	// Generate key pair for testing
	pub, _, err := curve25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create encryption instance
	encrypter, err := NewCurve25519Encryption(&pub, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create encrypter: %v", err)
	}

	// Test cases for various data sizes
	testCases := []struct {
		name        string
		dataSize    int
		shouldError bool
	}{
		{"Small data (64 bytes)", 64, false},
		{"Previous limit (222 bytes)", 222, false},
		{"Medium data (512 bytes)", 512, false},
		{"Large I2P data (1024 bytes)", 1024, false},
		{"Too large (1025 bytes)", 1025, true},
		{"Very large (2048 bytes)", 2048, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			// Fill with test data
			for i := range data {
				data[i] = byte(i % 256)
			}

			_, err := encrypter.Encrypt(data)
			if tc.shouldError && err == nil {
				t.Errorf("Expected error for %d bytes, but got none", tc.dataSize)
			} else if !tc.shouldError && err != nil {
				t.Errorf("Unexpected error for %d bytes: %v", tc.dataSize, err)
			}
		})
	}
}
