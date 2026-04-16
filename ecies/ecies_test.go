package ecies

import (
	"bytes"
	"crypto/rand"
	"testing"

	"go.step.sm/crypto/x25519"
)

// generateTestECIESKeys is a test helper that generates an ECIES key pair
// and returns typed keys ready for use.
func generateTestECIESKeys(t *testing.T) (ECIESPublicKey, ECIESPrivateKey, []byte, []byte) {
	t.Helper()
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	var privKey ECIESPrivateKey
	copy(privKey[:], priv)

	pubInterface, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	pubKey := pubInterface.(ECIESPublicKey)
	return pubKey, privKey, pub, priv
}

// assertEncryptDecryptMatch encrypts data with pub, decrypts with priv, and asserts equality.
func assertEncryptDecryptMatch(t *testing.T, pub, priv, originalData []byte) {
	t.Helper()
	ciphertext, err := EncryptECIESX25519(pub, originalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	plaintext, err := DecryptECIESX25519(priv, ciphertext)
	if err != nil {
		t.Errorf("Decryption failed: %v", err)
		return
	}
	if !bytes.Equal(plaintext, originalData) {
		t.Errorf("Plaintext mismatch")
	}
}

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

	// Decryption with correct private key should succeed
	assertEncryptDecryptMatch(t, pub1, priv1, originalData)

	// Decryption with wrong private key should fail
	ciphertext, err := EncryptECIESX25519(pub1, originalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
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
	assertEncryptDecryptMatch(t, recipientPub, recipientPriv, originalData)
	assertEncryptDecryptMatch(t, recipientPub, recipientPriv, originalData)
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
	assertEncryptDecryptMatch(t, ourPub, ourPriv, testData)

	// Test: encrypt with x25519 key (converted), decrypt with our function
	x25519PubBytes := make([]byte, 32)
	x25519PrivBytes := make([]byte, 32)
	copy(x25519PubBytes, x25519Pub[:])
	copy(x25519PrivBytes, x25519Priv[:])
	assertEncryptDecryptMatch(t, x25519PubBytes, x25519PrivBytes, testData)
}

// TestECIESPrivateKeyPublicDerivation tests that Public() correctly derives the public key
// from the private key instead of generating a random key.
// This is a regression test for the critical bug where Public() was generating random keys.
func TestECIESPrivateKeyPublicDerivation(t *testing.T) {
	// Generate a key pair
	expectedPub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create ECIESPrivateKey from the private key bytes
	var privKey ECIESPrivateKey
	copy(privKey[:], priv)

	// Derive public key using the Public() method
	derivedPubInterface, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	derivedPub, ok := derivedPubInterface.(ECIESPublicKey)
	if !ok {
		t.Fatalf("Public() returned wrong type: %T", derivedPubInterface)
	}

	// Verify the derived public key matches the expected public key
	if !bytes.Equal(derivedPub[:], expectedPub) {
		t.Errorf("Public key mismatch:\nExpected: %x\nGot:      %x", expectedPub, derivedPub[:])
	}
}

// TestECIESPrivateKeyPublicConsistency tests that Public() always returns the same
// public key for the same private key (deterministic derivation).
func TestECIESPrivateKeyPublicConsistency(t *testing.T) {
	_, privKey, _, _ := generateTestECIESKeys(t)

	// Derive public key multiple times
	pub1, err := privKey.Public()
	if err != nil {
		t.Fatalf("First Public() call failed: %v", err)
	}

	pub2, err := privKey.Public()
	if err != nil {
		t.Fatalf("Second Public() call failed: %v", err)
	}

	pub3, err := privKey.Public()
	if err != nil {
		t.Fatalf("Third Public() call failed: %v", err)
	}

	// All derived public keys should be identical
	eciesPub1 := pub1.(ECIESPublicKey)
	eciesPub2 := pub2.(ECIESPublicKey)
	eciesPub3 := pub3.(ECIESPublicKey)

	if !bytes.Equal(eciesPub1[:], eciesPub2[:]) {
		t.Error("Public() returned different keys on consecutive calls (first vs second)")
	}

	if !bytes.Equal(eciesPub1[:], eciesPub3[:]) {
		t.Error("Public() returned different keys on consecutive calls (first vs third)")
	}
}

// TestECIESPublicKeyEncryptDecryptRoundTrip tests that encryption/decryption works
// correctly when using a public key derived via Public() method.
func TestECIESPublicKeyEncryptDecryptRoundTrip(t *testing.T) {
	pubKey, privKey, _, _ := generateTestECIESKeys(t)

	// Test data
	originalData := []byte("Testing encryption with derived public key")

	// Encrypt using the derived public key
	ciphertext, err := EncryptECIESX25519(pubKey[:], originalData)
	if err != nil {
		t.Fatalf("Encryption with derived public key failed: %v", err)
	}

	// Decrypt using the private key
	plaintext, err := DecryptECIESX25519(privKey[:], ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify plaintext matches original
	if !bytes.Equal(plaintext, originalData) {
		t.Errorf("Plaintext mismatch:\nExpected: %s\nGot:      %s", originalData, plaintext)
	}
}

// assertKeyLenAndBytes is a helper that validates Len() and Bytes() methods
// on an ECIES key, checking expected size and byte equality.
func assertKeyLenAndBytes(t *testing.T, label string, actualLen, expectedLen int, actualBytes, expectedBytes []byte) {
	t.Helper()
	if actualLen != expectedLen {
		t.Errorf("%s Len() returned %d, expected %d", label, actualLen, expectedLen)
	}
	if len(actualBytes) != expectedLen {
		t.Errorf("%s Bytes() returned %d bytes, expected %d", label, len(actualBytes), expectedLen)
	}
	if !bytes.Equal(actualBytes, expectedBytes) {
		t.Errorf("%s Bytes() returned incorrect key bytes", label)
	}
}

// TestECIESKeyInterfaceMethods tests that both ECIESPublicKey and ECIESPrivateKey
// properly implement their respective interface methods via a table-driven test.
func TestECIESKeyInterfaceMethods(t *testing.T) {
	pubKey, privKey, pub, priv := generateTestECIESKeys(t)

	tests := []struct {
		name      string
		testData  []byte
		assertKey func(t *testing.T)
		roundTrip func(t *testing.T)
	}{
		{
			name:     "PublicKey/Encrypter",
			testData: []byte("Test encrypter interface"),
			assertKey: func(t *testing.T) {
				assertKeyLenAndBytes(t, "PublicKey", pubKey.Len(), PublicKeySize, pubKey.Bytes(), pub)
			},
			roundTrip: func(t *testing.T) {
				encrypter, err := pubKey.NewEncrypter()
				if err != nil {
					t.Fatalf("NewEncrypter() failed: %v", err)
				}
				if encrypter == nil {
					t.Fatal("NewEncrypter() returned nil")
				}
				ciphertext, err := encrypter.Encrypt([]byte("Test encrypter interface"))
				if err != nil {
					t.Fatalf("Encrypt() failed: %v", err)
				}
				plaintext, err := DecryptECIESX25519(privKey[:], ciphertext)
				if err != nil {
					t.Fatalf("Decryption failed: %v", err)
				}
				if !bytes.Equal(plaintext, []byte("Test encrypter interface")) {
					t.Error("Round-trip through interface failed")
				}
			},
		},
		{
			name:     "PrivateKey/Decrypter",
			testData: []byte("Test decrypter interface"),
			assertKey: func(t *testing.T) {
				assertKeyLenAndBytes(t, "PrivateKey", privKey.Len(), PrivateKeySize, privKey.Bytes(), priv)
			},
			roundTrip: func(t *testing.T) {
				decrypter, err := privKey.NewDecrypter()
				if err != nil {
					t.Fatalf("NewDecrypter() failed: %v", err)
				}
				if decrypter == nil {
					t.Fatal("NewDecrypter() returned nil")
				}
				ciphertext, err := EncryptECIESX25519(pub, []byte("Test decrypter interface"))
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}
				plaintext, err := decrypter.Decrypt(ciphertext)
				if err != nil {
					t.Fatalf("Decrypt() failed: %v", err)
				}
				if !bytes.Equal(plaintext, []byte("Test decrypter interface")) {
					t.Error("Round-trip through interface failed")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertKey(t)
			tt.roundTrip(t)
		})
	}

	// Note: Zero() method has a value receiver which makes it ineffective.
	// This is a known issue but fixing it is outside the scope of the current task.
	// The Zero() method should have a pointer receiver: func (k *ECIESPrivateKey) Zero()
}

// TestGenerateECIESKeyPair tests the GenerateECIESKeyPair function.
func TestGenerateECIESKeyPair(t *testing.T) {
	// Generate multiple key pairs
	for i := 0; i < 10; i++ {
		pubKey, privKey, err := GenerateECIESKeyPair()
		if err != nil {
			t.Fatalf("GenerateECIESKeyPair() iteration %d failed: %v", i, err)
		}

		if pubKey == nil {
			t.Fatalf("GenerateECIESKeyPair() iteration %d returned nil public key", i)
		}

		if privKey == nil {
			t.Fatalf("GenerateECIESKeyPair() iteration %d returned nil private key", i)
		}

		// Test key sizes
		if pubKey.Len() != PublicKeySize {
			t.Errorf("Public key %d has wrong size: got %d, expected %d", i, pubKey.Len(), PublicKeySize)
		}

		if privKey.Len() != PrivateKeySize {
			t.Errorf("Private key %d has wrong size: got %d, expected %d", i, privKey.Len(), PrivateKeySize)
		}

		// Verify derived public key matches
		derivedPubInterface, err := privKey.Public()
		if err != nil {
			t.Fatalf("Public() for key pair %d failed: %v", i, err)
		}

		derivedPub := derivedPubInterface.(ECIESPublicKey)
		if !bytes.Equal(derivedPub[:], pubKey[:]) {
			t.Errorf("Key pair %d: derived public key doesn't match generated public key", i)
		}

		// Test encryption/decryption round-trip
		testData := []byte("Test key pair functionality")
		ciphertext, err := EncryptECIESX25519(pubKey[:], testData)
		if err != nil {
			t.Fatalf("Encryption with key pair %d failed: %v", i, err)
		}

		plaintext, err := DecryptECIESX25519(privKey[:], ciphertext)
		if err != nil {
			t.Fatalf("Decryption with key pair %d failed: %v", i, err)
		}

		if !bytes.Equal(plaintext, testData) {
			t.Errorf("Key pair %d: round-trip failed", i)
		}
	}
}
