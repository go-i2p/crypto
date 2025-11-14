// Package tunnel provides I2P tunnel encryption implementations.
// This file tests the ECIES-X25519 tunnel encryption wrapper functionality.
package tunnel

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/go-i2p/crypto/ecies"
)

func TestNewECIESEncryptor(t *testing.T) {
	tests := []struct {
		name            string
		recipientPubKey [32]byte
		expectType      TunnelEncryptionType
	}{
		{
			name:            "valid_recipient_public_key",
			recipientPubKey: generateTestPublicKey(t),
			expectType:      TunnelEncryptionECIES,
		},
		{
			name:            "zero_public_key",
			recipientPubKey: [32]byte{}, // Zero key
			expectType:      TunnelEncryptionECIES,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptor := NewECIESEncryptor(tt.recipientPubKey)

			if encryptor == nil {
				t.Error("NewECIESEncryptor() returned nil")
				return
			}

			if encryptor.Type() != tt.expectType {
				t.Errorf("ECIESEncryptor.Type() = %v, want %v", encryptor.Type(), tt.expectType)
			}

			// Verify the public key was stored correctly
			if !bytes.Equal(encryptor.recipientPubKey[:], tt.recipientPubKey[:]) {
				t.Error("ECIESEncryptor did not store recipient public key correctly")
			}
		})
	}
}

func TestNewECIESDecryptor(t *testing.T) {
	tests := []struct {
		name             string
		recipientPrivKey [32]byte
		expectType       TunnelEncryptionType
	}{
		{
			name:             "valid_recipient_private_key",
			recipientPrivKey: generateTestPrivateKey(t),
			expectType:       TunnelEncryptionECIES,
		},
		{
			name:             "zero_private_key",
			recipientPrivKey: [32]byte{}, // Zero key
			expectType:       TunnelEncryptionECIES,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decryptor := NewECIESDecryptor(tt.recipientPrivKey)

			if decryptor == nil {
				t.Error("NewECIESDecryptor() returned nil")
				return
			}

			if decryptor.Type() != tt.expectType {
				t.Errorf("ECIESDecryptor.Type() = %v, want %v", decryptor.Type(), tt.expectType)
			}

			// Verify the private key was stored correctly
			if !bytes.Equal(decryptor.recipientPrivKey[:], tt.recipientPrivKey[:]) {
				t.Error("ECIESDecryptor did not store recipient private key correctly")
			}
		})
	}
}

func TestECIESEncryptor_Encrypt(t *testing.T) {
	// Generate a test key pair
	pubKey, _, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	var recipientPubKey [32]byte
	copy(recipientPubKey[:], pubKey[:])

	encryptor := NewECIESEncryptor(recipientPubKey)

	tests := []struct {
		name      string
		plaintext []byte
		wantErr   bool
	}{
		{
			name:      "empty_data",
			plaintext: []byte{},
			wantErr:   false,
		},
		{
			name:      "nil_data",
			plaintext: nil,
			wantErr:   false,
		},
		{
			name:      "small_data",
			plaintext: []byte("Hello, I2P tunnel!"),
			wantErr:   false,
		},
		{
			name:      "medium_data",
			plaintext: make([]byte, 256),
			wantErr:   false,
		},
		{
			name:      "large_data",
			plaintext: make([]byte, 1000),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill test data with random bytes for non-empty cases
			if len(tt.plaintext) > 0 {
				rand.Read(tt.plaintext)
			}

			ciphertext, err := encryptor.Encrypt(tt.plaintext)

			if (err != nil) != tt.wantErr {
				t.Errorf("ECIESEncryptor.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify ciphertext is longer than plaintext (due to ECIES overhead)
				expectedMinLen := len(tt.plaintext) + 32 + 12 + 16 // pubkey + nonce + tag
				if len(ciphertext) < expectedMinLen {
					t.Errorf("ECIESEncryptor.Encrypt() ciphertext too short: got %d, want >= %d", len(ciphertext), expectedMinLen)
				}

				// Verify ciphertext is not the same as plaintext
				if len(tt.plaintext) > 0 && bytes.Equal(ciphertext[:len(tt.plaintext)], tt.plaintext) {
					t.Error("ECIESEncryptor.Encrypt() returned plaintext unchanged")
				}
			}
		})
	}
}

func TestECIESDecryptor_Decrypt(t *testing.T) {
	// Generate a test key pair
	pubKey, privKey, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	var recipientPrivKey [32]byte
	copy(recipientPrivKey[:], privKey[:])

	decryptor := NewECIESDecryptor(recipientPrivKey)

	tests := []struct {
		name      string
		plaintext []byte
		wantErr   bool
	}{
		{
			name:      "empty_data",
			plaintext: []byte{},
			wantErr:   false,
		},
		{
			name:      "small_data",
			plaintext: []byte("Hello, I2P tunnel!"),
			wantErr:   false,
		},
		{
			name:      "medium_data",
			plaintext: make([]byte, 256),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill test data with random bytes for non-empty cases
			if len(tt.plaintext) > 0 {
				rand.Read(tt.plaintext)
			}

			// First encrypt the data using the ecies package directly
			ciphertext, err := ecies.EncryptECIESX25519(pubKey[:], tt.plaintext)
			if err != nil {
				t.Fatalf("Failed to encrypt test data: %v", err)
			}

			// Now decrypt using our wrapper
			decrypted, err := decryptor.Decrypt(ciphertext)

			if (err != nil) != tt.wantErr {
				t.Errorf("ECIESDecryptor.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify decrypted data matches original plaintext
				if !bytes.Equal(decrypted, tt.plaintext) {
					t.Errorf("ECIESDecryptor.Decrypt() = %v, want %v", decrypted, tt.plaintext)
				}
			}
		})
	}
}

func TestECIESDecryptor_Decrypt_NilCiphertext(t *testing.T) {
	privKey := generateTestPrivateKey(t)
	decryptor := NewECIESDecryptor(privKey)

	_, err := decryptor.Decrypt(nil)
	if err == nil {
		t.Error("ECIESDecryptor.Decrypt() with nil ciphertext should return error")
	}
}

func TestECIESEncryptor_Decrypt_ShouldFail(t *testing.T) {
	pubKey := generateTestPublicKey(t)
	encryptor := NewECIESEncryptor(pubKey)

	// Encryptor should not support decryption
	_, err := encryptor.Decrypt([]byte("some ciphertext"))
	if err == nil {
		t.Error("ECIESEncryptor.Decrypt() should return error (encryptors don't decrypt)")
	}
}

func TestECIESDecryptor_Encrypt_ShouldFail(t *testing.T) {
	privKey := generateTestPrivateKey(t)
	decryptor := NewECIESDecryptor(privKey)

	// Decryptor should not support encryption
	_, err := decryptor.Encrypt([]byte("some plaintext"))
	if err == nil {
		t.Error("ECIESDecryptor.Encrypt() should return error (decryptors don't encrypt)")
	}
}

func TestECIESEncryptorDecryptor_RoundTrip(t *testing.T) {
	// Generate a test key pair
	pubKey, privKey, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	var recipientPubKey [32]byte
	var recipientPrivKey [32]byte
	copy(recipientPubKey[:], pubKey[:])
	copy(recipientPrivKey[:], privKey[:])

	encryptor := NewECIESEncryptor(recipientPubKey)
	decryptor := NewECIESDecryptor(recipientPrivKey)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "empty_data",
			plaintext: []byte{},
		},
		{
			name:      "small_message",
			plaintext: []byte("Hello, I2P tunnel encryption!"),
		},
		{
			name:      "pattern_data",
			plaintext: bytes.Repeat([]byte{0xAA, 0x55}, 128), // 256 bytes of pattern
		},
		{
			name:      "random_data",
			plaintext: make([]byte, 512),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill test data with random bytes for random test
			if tt.name == "random_data" {
				rand.Read(tt.plaintext)
			}

			// Encrypt the plaintext
			ciphertext, err := encryptor.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("ECIESEncryptor.Encrypt() failed: %v", err)
			}

			// Decrypt the ciphertext
			decrypted, err := decryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("ECIESDecryptor.Decrypt() failed: %v", err)
			}

			// Verify round-trip success
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Round-trip failed: got %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestECIESDecryptor_Zero(t *testing.T) {
	// Create a decryptor with a known private key
	privKey := [32]byte{}
	for i := range privKey {
		privKey[i] = byte(i) // Fill with test pattern
	}

	decryptor := NewECIESDecryptor(privKey)

	// Verify key is set
	if bytes.Equal(decryptor.recipientPrivKey[:], make([]byte, 32)) {
		t.Error("Private key should not be zero before Zero() call")
	}

	// Call Zero() to clear the key
	decryptor.Zero()

	// Verify key is now zeroed
	if !bytes.Equal(decryptor.recipientPrivKey[:], make([]byte, 32)) {
		t.Error("Private key should be zero after Zero() call")
	}
}

func TestECIESWrapper_MatchesECIESPackage(t *testing.T) {
	// Generate a test key pair
	pubKey, privKey, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	var recipientPubKey [32]byte
	var recipientPrivKey [32]byte
	copy(recipientPubKey[:], pubKey[:])
	copy(recipientPrivKey[:], privKey[:])

	encryptor := NewECIESEncryptor(recipientPubKey)
	decryptor := NewECIESDecryptor(recipientPrivKey)

	plaintext := []byte("Test message for ECIES wrapper validation")

	// Test 1: Our wrapper encrypt should match direct ecies package
	wrapperCiphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Wrapper encrypt failed: %v", err)
	}

	// Direct decryption using ecies package should work
	directDecrypted, err := ecies.DecryptECIESX25519(privKey[:], wrapperCiphertext)
	if err != nil {
		t.Fatalf("Direct ecies decrypt of wrapper ciphertext failed: %v", err)
	}

	if !bytes.Equal(directDecrypted, plaintext) {
		t.Error("Wrapper encryption not compatible with direct ecies decryption")
	}

	// Test 2: Our wrapper decrypt should handle direct ecies ciphertext
	directCiphertext, err := ecies.EncryptECIESX25519(pubKey[:], plaintext)
	if err != nil {
		t.Fatalf("Direct ecies encrypt failed: %v", err)
	}

	wrapperDecrypted, err := decryptor.Decrypt(directCiphertext)
	if err != nil {
		t.Fatalf("Wrapper decrypt of direct ciphertext failed: %v", err)
	}

	if !bytes.Equal(wrapperDecrypted, plaintext) {
		t.Error("Wrapper decryption not compatible with direct ecies encryption")
	}
}

// Helper function to generate a test public key
func generateTestPublicKey(t *testing.T) [32]byte {
	pubKey, _, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test public key: %v", err)
	}

	var result [32]byte
	copy(result[:], pubKey[:])
	return result
}

// Helper function to generate a test private key
func generateTestPrivateKey(t *testing.T) [32]byte {
	_, privKey, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test private key: %v", err)
	}

	var result [32]byte
	copy(result[:], privKey[:])
	return result
}

// Benchmark tests for performance validation
func BenchmarkECIESEncryptor_Encrypt(b *testing.B) {
	pubKey, _, err := ecies.GenerateKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate test key pair: %v", err)
	}

	var recipientPubKey [32]byte
	copy(recipientPubKey[:], pubKey[:])

	encryptor := NewECIESEncryptor(recipientPubKey)
	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.Encrypt(plaintext)
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}
	}
}

func BenchmarkECIESDecryptor_Decrypt(b *testing.B) {
	pubKey, privKey, err := ecies.GenerateKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate test key pair: %v", err)
	}

	var recipientPrivKey [32]byte
	copy(recipientPrivKey[:], privKey[:])

	decryptor := NewECIESDecryptor(recipientPrivKey)
	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	// Pre-encrypt the data for benchmarking
	ciphertext, err := ecies.EncryptECIESX25519(pubKey[:], plaintext)
	if err != nil {
		b.Fatalf("Failed to encrypt test data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decryptor.Decrypt(ciphertext)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
	}
}
