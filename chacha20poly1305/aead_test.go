package chacha20poly1305

import (
	"bytes"
	"fmt"
	"testing"
)

// TestAEADEncryptDecrypt tests basic encryption and decryption
func TestAEADEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name           string
		plaintext      []byte
		associatedData []byte
	}{
		{
			name:           "empty plaintext",
			plaintext:      []byte{},
			associatedData: []byte{},
		},
		{
			name:           "short message",
			plaintext:      []byte("Hello, I2P!"),
			associatedData: []byte("metadata"),
		},
		{
			name:           "exact block size",
			plaintext:      make([]byte, 64),
			associatedData: []byte("header"),
		},
		{
			name:           "large message",
			plaintext:      make([]byte, 10000),
			associatedData: []byte("large AAD data here"),
		},
		{
			name:           "no associated data",
			plaintext:      []byte("Secret message"),
			associatedData: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			aead, err := NewAEAD(key)
			if err != nil {
				t.Fatalf("NewAEAD failed: %v", err)
			}

			nonce, err := GenerateNonce()
			if err != nil {
				t.Fatalf("GenerateNonce failed: %v", err)
			}

			ciphertext, tag, err := aead.Encrypt(tt.plaintext, tt.associatedData, nonce[:])
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			if len(ciphertext) != len(tt.plaintext) {
				t.Errorf("ciphertext length mismatch: got %d, want %d", len(ciphertext), len(tt.plaintext))
			}

			if len(tag) != TagSize {
				t.Errorf("tag length mismatch: got %d, want %d", len(tag), TagSize)
			}

			decrypted, err := aead.Decrypt(ciphertext, tag[:], tt.associatedData, nonce[:])
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("decrypted plaintext mismatch")
			}
		})
	}
}

// TestAEADAuthenticationFailure tests that tampering is detected
func TestAEADAuthenticationFailure(t *testing.T) {
	key, _ := GenerateKey()
	aead, _ := NewAEAD(key)
	nonce, _ := GenerateNonce()

	plaintext := []byte("Secret message")
	aad := []byte("metadata")

	ciphertext, tag, err := aead.Encrypt(plaintext, aad, nonce[:])
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Test tampered ciphertext
	tamperedCt := make([]byte, len(ciphertext))
	copy(tamperedCt, ciphertext)
	if len(tamperedCt) > 0 {
		tamperedCt[0] ^= 0xFF
	}

	_, err = aead.Decrypt(tamperedCt, tag[:], aad, nonce[:])
	if err == nil {
		t.Error("expected error for tampered ciphertext, got nil")
	}

	// Test tampered tag
	tamperedTag := make([]byte, len(tag))
	copy(tamperedTag, tag[:])
	tamperedTag[0] ^= 0xFF

	_, err = aead.Decrypt(ciphertext, tamperedTag, aad, nonce[:])
	if err == nil {
		t.Error("expected error for tampered tag, got nil")
	}
}

// TestAEADInvalidInputs tests error handling for invalid inputs
func TestAEADInvalidInputs(t *testing.T) {
	key, _ := GenerateKey()
	aead, _ := NewAEAD(key)

	tests := []struct {
		name      string
		nonce     []byte
		wantError error
	}{
		{
			name:      "short nonce",
			nonce:     make([]byte, NonceSize-1),
			wantError: ErrInvalidNonceSize,
		},
		{
			name:      "long nonce",
			nonce:     make([]byte, NonceSize+1),
			wantError: ErrInvalidNonceSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := []byte("test")

			_, _, err := aead.Encrypt(plaintext, nil, tt.nonce)
			if err == nil && tt.wantError != nil {
				t.Error("Encrypt: expected error, got nil")
			}
		})
	}
}

// BenchmarkAEADEncrypt benchmarks encryption performance
func BenchmarkAEADEncrypt(b *testing.B) {
	key, _ := GenerateKey()
	aead, _ := NewAEAD(key)
	nonce, _ := GenerateNonce()

	sizes := []int{64, 512, 1024, 4096}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			plaintext := make([]byte, size)
			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _, _ = aead.Encrypt(plaintext, nil, nonce[:])
			}
		})
	}
}

// BenchmarkAEADDecrypt benchmarks decryption performance
func BenchmarkAEADDecrypt(b *testing.B) {
	key, _ := GenerateKey()
	aead, _ := NewAEAD(key)
	nonce, _ := GenerateNonce()

	sizes := []int{64, 512, 1024, 4096}

	for _, size := range sizes {
		plaintext := make([]byte, size)
		ciphertext, tag, _ := aead.Encrypt(plaintext, nil, nonce[:])

		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = aead.Decrypt(ciphertext, tag[:], nil, nonce[:])
			}
		})
	}
}
