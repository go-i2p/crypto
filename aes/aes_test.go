package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestAESEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32) // 256-bit key
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	_, err = rand.Read(iv)
	if err != nil {
		t.Fatalf("Failed to generate random IV: %v", err)
	}

	symmetricKey := AESSymmetricKey{
		Key: key,
		IV:  iv,
	}

	encrypter, err := symmetricKey.NewEncrypter()
	if err != nil {
		log.Fatalf("Error creating encrypter: %v", err)
	}

	decrypter, err := symmetricKey.NewDecrypter()
	if err != nil {
		log.Fatalf("Error creating decrypter: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty string", []byte("")},
		{"Short string", []byte("Hello, World!")},
		{"Long string", bytes.Repeat([]byte("A"), 1000)},
		{"Exact block size", bytes.Repeat([]byte("A"), aes.BlockSize)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := encrypter.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := decrypter.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Errorf("Decrypted text doesn't match original plaintext.\nOriginal: %s\nDecrypted: %s",
					hex.EncodeToString(tc.plaintext), hex.EncodeToString(decrypted))
			}
		})
	}
}

func TestAESEncryptInvalidKey(t *testing.T) {
	invalidKeys := [][]byte{
		make([]byte, 15), // Too short
		make([]byte, 17), // Invalid length
		make([]byte, 31), // Too short for AES-256
		make([]byte, 33), // Too long
		make([]byte, 0),  // Empty
		nil,              // Nil
	}

	plaintext := []byte("Test plaintext")
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)

	for _, key := range invalidKeys {
		symmetricKey := &AESSymmetricKey{
			Key: key,
			IV:  iv,
		}
		encrypter, err := symmetricKey.NewEncrypter()
		if err == nil {
			_, err = encrypter.Encrypt(plaintext)
		}
		if err == nil {
			t.Errorf("Expected error for invalid key length %d, but got none", len(key))
		} else {
			t.Logf("Correctly got error for key length %d: %v", len(key), err)
		}
	}
}

func TestAESDecryptInvalidInput(t *testing.T) {
	key := make([]byte, 32) // Valid key length for AES-256
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	symmetricKey := &AESSymmetricKey{
		Key: key,
		IV:  iv,
	}
	decrypter, err := symmetricKey.NewDecrypter()
	if err != nil {
		t.Fatalf("Failed to create decrypter: %v", err)
	}

	invalidCiphertexts := [][]byte{
		make([]byte, 15), // Not a multiple of block size
		make([]byte, 0),  // Empty
		nil,              // Nil
	}

	for _, ciphertext := range invalidCiphertexts {
		_, err := decrypter.Decrypt(ciphertext)
		if err == nil {
			t.Errorf("Expected error for invalid ciphertext length %d, but got none", len(ciphertext))
		} else {
			t.Logf("Correctly got error for ciphertext length %d: %v", len(ciphertext), err)
		}
	}
}

func TestPKCS7PadUnpad(t *testing.T) {
	testCases := []struct {
		name      string
		input     []byte
		blockSize int
	}{
		{"Empty input", []byte{}, 16},
		{"Exact block size", bytes.Repeat([]byte("A"), 16), 16},
		{"One byte short", bytes.Repeat([]byte("A"), 15), 16},
		{"Multiple blocks", bytes.Repeat([]byte("A"), 32), 16},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := pkcs7Pad(tc.input, tc.blockSize)
			if len(padded)%tc.blockSize != 0 {
				t.Errorf("Padded data length (%d) is not a multiple of block size (%d)", len(padded), tc.blockSize)
			}

			unpadded, err := pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("Unpadding failed: %v", err)
			}

			if !bytes.Equal(tc.input, unpadded) {
				t.Errorf("Unpadded data doesn't match original input.\nOriginal: %s\nUnpadded: %s",
					hex.EncodeToString(tc.input), hex.EncodeToString(unpadded))
			}
		})
	}
}

func TestPKCS7UnpadInvalidInput(t *testing.T) {
	invalidInputs := []struct {
		name  string
		input []byte
	}{
		{"Empty slice", []byte{}},
		{"Invalid padding value", []byte{1, 2, 3, 4, 0}},                                 // Padding value 0 is invalid
		{"Padding larger than block size", append(bytes.Repeat([]byte{17}, 17))},         // Padding value 17 (>16) is invalid
		{"Incorrect padding bytes", []byte{1, 2, 3, 4, 5, 6, 2, 3, 3}},                   // Last padding bytes do not match padding value
		{"Valid block size but invalid padding", append(bytes.Repeat([]byte{1}, 15), 3)}, // Padding value 3, but bytes are 1
	}

	for _, tc := range invalidInputs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pkcs7Unpad(tc.input)
			if err == nil {
				t.Errorf("Expected error for invalid input %v, but got none", tc.input)
			}
		})
	}
}

// TestAESConstructorValidation tests that NewEncrypter and NewDecrypter validate keys early
func TestAESConstructorValidation(t *testing.T) {
	testCases := []struct {
		name          string
		keySize       int
		ivSize        int
		expectSuccess bool
		description   string
	}{
		{"AES128_valid", 16, 16, true, "Valid AES-128 key and IV"},
		{"AES192_valid", 24, 16, true, "Valid AES-192 key and IV"},
		{"AES256_valid", 32, 16, true, "Valid AES-256 key and IV"},
		{"invalid_key_15", 15, 16, false, "Invalid key size: 15 bytes"},
		{"invalid_key_17", 17, 16, false, "Invalid key size: 17 bytes"},
		{"invalid_key_0", 0, 16, false, "Invalid key size: 0 bytes"},
		{"invalid_iv_15", 16, 15, false, "Invalid IV size: 15 bytes"},
		{"invalid_iv_17", 16, 17, false, "Invalid IV size: 17 bytes"},
		{"invalid_iv_0", 16, 0, false, "Invalid IV size: 0 bytes"},
		{"both_invalid", 15, 15, false, "Both key and IV invalid"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create key with specified sizes
			key := &AESSymmetricKey{
				Key: make([]byte, tc.keySize),
				IV:  make([]byte, tc.ivSize),
			}

			// Test NewEncrypter
			encrypter, encErr := key.NewEncrypter()
			if tc.expectSuccess {
				if encErr != nil {
					t.Errorf("NewEncrypter failed for %s: %v", tc.description, encErr)
				}
				if encrypter == nil {
					t.Errorf("NewEncrypter returned nil encrypter for %s", tc.description)
				}
			} else {
				if encErr == nil {
					t.Errorf("NewEncrypter should have failed for %s", tc.description)
				}
				if encrypter != nil {
					t.Errorf("NewEncrypter should have returned nil encrypter for %s", tc.description)
				}
			}

			// Test NewDecrypter
			decrypter, decErr := key.NewDecrypter()
			if tc.expectSuccess {
				if decErr != nil {
					t.Errorf("NewDecrypter failed for %s: %v", tc.description, decErr)
				}
				if decrypter == nil {
					t.Errorf("NewDecrypter returned nil decrypter for %s", tc.description)
				}
			} else {
				if decErr == nil {
					t.Errorf("NewDecrypter should have failed for %s", tc.description)
				}
				if decrypter != nil {
					t.Errorf("NewDecrypter should have returned nil decrypter for %s", tc.description)
				}
			}
		})
	}
}

// TestAESZeroMethod tests that Zero() method securely clears key material
func TestAESZeroMethod(t *testing.T) {
	// Create test key with known data
	key := &AESSymmetricKey{
		Key: []byte("this_is_a_test_key_32_bytes_long"), // 32 bytes for AES-256
		IV:  []byte("test_iv_16_bytes"),                 // 16 bytes for AES IV
	}

	// Verify key and IV have non-zero data initially
	keyHasData := false
	for _, b := range key.Key {
		if b != 0 {
			keyHasData = true
			break
		}
	}
	if !keyHasData {
		t.Error("Test key should have non-zero data initially")
	}

	ivHasData := false
	for _, b := range key.IV {
		if b != 0 {
			ivHasData = true
			break
		}
	}
	if !ivHasData {
		t.Error("Test IV should have non-zero data initially")
	}

	// Call Zero() method
	key.Zero()

	// Verify all key bytes are zero
	for i, b := range key.Key {
		if b != 0 {
			t.Errorf("Key byte %d is %d, expected 0 after Zero()", i, b)
		}
	}

	// Verify all IV bytes are zero
	for i, b := range key.IV {
		if b != 0 {
			t.Errorf("IV byte %d is %d, expected 0 after Zero()", i, b)
		}
	}

	t.Log("AES Zero() method successfully cleared all key material")
}
