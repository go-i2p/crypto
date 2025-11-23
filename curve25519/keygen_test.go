package curve25519

import (
	"testing"
)

func TestGenerateX25519KeyPair(t *testing.T) {
	pubKey, privKey, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	if pubKey == nil {
		t.Error("Public key is nil")
	}

	if privKey == nil {
		t.Error("Private key is nil")
	}

	// Verify key sizes
	if len(*pubKey) != 32 {
		t.Errorf("Public key size: expected 32, got %d", len(*pubKey))
	}

	if len(*privKey) != 32 {
		t.Errorf("Private key size: expected 32, got %d", len(*privKey))
	}

	// Verify can create encrypter
	encrypter, err := pubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("NewEncrypter failed: %v", err)
	}

	// Verify can create decrypter
	decrypter, err := privKey.NewDecrypter()
	if err != nil {
		t.Fatalf("NewDecrypter failed: %v", err)
	}

	// Test encryption and decryption
	plaintext := []byte("test message")
	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := decrypter.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
	}
}
