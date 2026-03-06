package curve25519

import (
	"testing"
)

func TestGenerateX25519KeyPair(t *testing.T) {
	pubKey, privKey, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	// Verify keys are non-nil with correct sizes
	for _, tc := range []struct {
		name string
		key  interface{ Bytes() []byte }
		size int
	}{
		{"PublicKey", pubKey, 32},
		{"PrivateKey", privKey, 32},
	} {
		if tc.key == nil {
			t.Fatalf("%s is nil", tc.name)
		}
		if got := len(tc.key.Bytes()); got != tc.size {
			t.Errorf("%s size: expected %d, got %d", tc.name, tc.size, got)
		}
	}

	// Verify encrypt/decrypt round-trip
	encrypter, err := pubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("NewEncrypter failed: %v", err)
	}
	decrypter, err := privKey.NewDecrypter()
	if err != nil {
		t.Fatalf("NewDecrypter failed: %v", err)
	}

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
