package ecies

import (
	"bytes"
	"crypto/rand"
	"testing"

	"go.step.sm/crypto/x25519"
)

func TestECIESX25519RoundTrip(t *testing.T) {
	// Generate recipient key pair
	recipientPub, recipientPriv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	// Test data of various sizes
	testCases := []struct {
		name string
		data []byte
	}{
		{"Empty data", []byte{}},
		{"Small data", []byte("Hello, I2P!")},
		{"Medium data", make([]byte, 256)},
		{"Large data", make([]byte, 1024)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill test data with pattern
			for i := range tc.data {
				tc.data[i] = byte(i % 256)
			}

			// Encrypt
			ciphertext, err := EncryptECIESX25519(recipientPub, tc.data)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify ciphertext format and size
			expectedMinSize := PublicKeySize + NonceSize + TagSize + len(tc.data)
			if len(ciphertext) < expectedMinSize {
				t.Errorf("Ciphertext too short: got %d, expected at least %d",
					len(ciphertext), expectedMinSize)
			}

			// Decrypt
			plaintext, err := DecryptECIESX25519(recipientPriv, ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify plaintext matches original
			if !bytes.Equal(plaintext, tc.data) {
				t.Errorf("Plaintext mismatch:\nExpected: %x\nGot:      %x",
					tc.data, plaintext)
			}
		})
	}
}

func TestECIESX25519DataSizeLimit(t *testing.T) {
	// Generate recipient key pair
	recipientPub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	// Test data size limits
	testCases := []struct {
		name        string
		dataSize    int
		shouldError bool
	}{
		{"Maximum allowed size", MaxPlaintextSize, false},
		{"Just over limit", MaxPlaintextSize + 1, true},
		{"Much larger", MaxPlaintextSize * 2, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.dataSize)

			_, err := EncryptECIESX25519(recipientPub, data)
			if tc.shouldError && err == nil {
				t.Errorf("Expected error for %d bytes, but got none", tc.dataSize)
			} else if !tc.shouldError && err != nil {
				t.Errorf("Unexpected error for %d bytes: %v", tc.dataSize, err)
			}
		})
	}
}

func TestECIESX25519InvalidInputs(t *testing.T) {
	// Generate valid key pair for comparison
	validPub, validPriv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate valid key pair: %v", err)
	}

	// Create valid ciphertext for decryption tests
	validCiphertext, err := EncryptECIESX25519(validPub, []byte("test"))
	if err != nil {
		t.Fatalf("Failed to create valid ciphertext: %v", err)
	}

	// Test encryption with invalid public keys
	t.Run("Encrypt with invalid public key", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			make([]byte, 31), // Too short
			make([]byte, 33), // Too long
		}

		for i, invalidKey := range invalidKeys {
			_, err := EncryptECIESX25519(invalidKey, []byte("test"))
			if err == nil {
				t.Errorf("Case %d: Expected error with invalid public key, got none", i)
			}
		}
	})

	// Test decryption with invalid private keys
	t.Run("Decrypt with invalid private key", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			make([]byte, 31), // Too short
			make([]byte, 33), // Too long
		}

		for i, invalidKey := range invalidKeys {
			_, err := DecryptECIESX25519(invalidKey, validCiphertext)
			if err == nil {
				t.Errorf("Case %d: Expected error with invalid private key, got none", i)
			}
		}
	})

	// Test decryption with invalid ciphertexts
	t.Run("Decrypt with invalid ciphertext", func(t *testing.T) {
		invalidCiphertexts := [][]byte{
			nil,
			{},
			make([]byte, PublicKeySize+NonceSize+TagSize-1), // Too short
			make([]byte, 10), // Way too short
		}

		for i, invalidCiphertext := range invalidCiphertexts {
			_, err := DecryptECIESX25519(validPriv, invalidCiphertext)
			if err == nil {
				t.Errorf("Case %d: Expected error with invalid ciphertext, got none", i)
			}
		}
	})
}

func TestECIESX25519CorruptedCiphertext(t *testing.T) {
	// Generate recipient key pair
	recipientPub, recipientPriv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	originalData := []byte("Secret message for I2P network")

	// Encrypt
	ciphertext, err := EncryptECIESX25519(recipientPub, originalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Test corruption at different positions
	testCases := []struct {
		name     string
		position int
	}{
		{"Corrupt ephemeral public key", 0},
		{"Corrupt nonce", PublicKeySize},
		{"Corrupt ciphertext", PublicKeySize + NonceSize},
		{"Corrupt authentication tag", len(ciphertext) - 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Make a copy and corrupt one byte
			corruptedCiphertext := make([]byte, len(ciphertext))
			copy(corruptedCiphertext, ciphertext)
			corruptedCiphertext[tc.position] ^= 0xFF // Flip all bits

			// Attempt decryption - should fail
			_, err := DecryptECIESX25519(recipientPriv, corruptedCiphertext)
			if err == nil {
				t.Errorf("Expected decryption to fail with corrupted data at position %d", tc.position)
			}
		})
	}
}

func TestECIESX25519DifferentKeys(t *testing.T) {
	// Generate two different key pairs
	pub1, priv1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate first key pair: %v", err)
	}

	_, priv2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate second key pair: %v", err)
	}

	// Encrypt with first public key
	originalData := []byte("This should only decrypt with the correct private key")
	ciphertext, err := EncryptECIESX25519(pub1, originalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decryption with correct private key should succeed
	plaintext, err := DecryptECIESX25519(priv1, ciphertext)
	if err != nil {
		t.Errorf("Decryption with correct private key failed: %v", err)
	} else if !bytes.Equal(plaintext, originalData) {
		t.Errorf("Plaintext mismatch with correct key")
	}

	// Decryption with wrong private key should fail
	_, err = DecryptECIESX25519(priv2, ciphertext)
	if err == nil {
		t.Errorf("Expected decryption to fail with wrong private key")
	}
}

func TestECIESX25519Deterministic(t *testing.T) {
	// Generate recipient key pair
	recipientPub, recipientPriv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	originalData := []byte("Deterministic test data")

	// Encrypt same data multiple times
	ciphertext1, err := EncryptECIESX25519(recipientPub, originalData)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	ciphertext2, err := EncryptECIESX25519(recipientPub, originalData)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Ciphertexts should be different (due to random ephemeral keys and nonces)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Ciphertexts should be different for same plaintext (non-deterministic)")
	}

	// Both should decrypt to same plaintext
	plaintext1, err := DecryptECIESX25519(recipientPriv, ciphertext1)
	if err != nil {
		t.Errorf("Decryption of first ciphertext failed: %v", err)
	}

	plaintext2, err := DecryptECIESX25519(recipientPriv, ciphertext2)
	if err != nil {
		t.Errorf("Decryption of second ciphertext failed: %v", err)
	}

	if !bytes.Equal(plaintext1, originalData) || !bytes.Equal(plaintext2, originalData) {
		t.Error("Both plaintexts should match original data")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	// Generate multiple key pairs
	for i := 0; i < 10; i++ {
		pub, priv, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Key generation %d failed: %v", i, err)
		}

		// Check key sizes
		if len(pub) != PublicKeySize {
			t.Errorf("Public key %d wrong size: got %d, expected %d", i, len(pub), PublicKeySize)
		}

		if len(priv) != PrivateKeySize {
			t.Errorf("Private key %d wrong size: got %d, expected %d", i, len(priv), PrivateKeySize)
		}

		// Verify keys are different from all-zeros
		allZerosPub := make([]byte, PublicKeySize)
		allZerosPriv := make([]byte, PrivateKeySize)

		if bytes.Equal(pub, allZerosPub) {
			t.Errorf("Public key %d is all zeros", i)
		}

		if bytes.Equal(priv, allZerosPriv) {
			t.Errorf("Private key %d is all zeros", i)
		}
	}
}

func TestECIESX25519CompatibilityWithX25519(t *testing.T) {
	// Test compatibility with go.step.sm/crypto/x25519

	// Generate key using our function
	ourPub, ourPriv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Our key generation failed: %v", err)
	}

	// Generate key using x25519 directly
	x25519Pub, x25519Priv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("X25519 key generation failed: %v", err)
	}

	// Test: encrypt with our key, decrypt with x25519 (converted)
	testData := []byte("Cross-compatibility test")

	ciphertext, err := EncryptECIESX25519(ourPub, testData)
	if err != nil {
		t.Fatalf("Encryption with our key failed: %v", err)
	}

	// Convert our private key to x25519 format and decrypt
	plaintext, err := DecryptECIESX25519(ourPriv, ciphertext)
	if err != nil {
		t.Fatalf("Decryption with our key failed: %v", err)
	}

	if !bytes.Equal(plaintext, testData) {
		t.Error("Round-trip with our keys failed")
	}

	// Test: encrypt with x25519 key (converted), decrypt with our function
	x25519PubBytes := make([]byte, 32)
	x25519PrivBytes := make([]byte, 32)
	copy(x25519PubBytes, x25519Pub[:])
	copy(x25519PrivBytes, x25519Priv[:])

	ciphertext2, err := EncryptECIESX25519(x25519PubBytes, testData)
	if err != nil {
		t.Fatalf("Encryption with x25519 key failed: %v", err)
	}

	plaintext2, err := DecryptECIESX25519(x25519PrivBytes, ciphertext2)
	if err != nil {
		t.Fatalf("Decryption with x25519 key failed: %v", err)
	}

	if !bytes.Equal(plaintext2, testData) {
		t.Error("Round-trip with x25519 keys failed")
	}
}
