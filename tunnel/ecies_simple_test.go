package tunnel

import (
	"bytes"
	"testing"

	"github.com/go-i2p/crypto/ecies"
)

func TestECIESEncryptor_Simple(t *testing.T) {
	// Generate a test key pair
	pubKey, _, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	var recipientPubKey [32]byte
	copy(recipientPubKey[:], pubKey[:])

	encryptor := NewECIESEncryptor(recipientPubKey)

	if encryptor == nil {
		t.Error("NewECIESEncryptor() returned nil")
		return
	}

	if encryptor.Type() != TunnelEncryptionECIES {
		t.Errorf("ECIESEncryptor.Type() = %v, want %v", encryptor.Type(), TunnelEncryptionECIES)
	}

	// Test encryption
	plaintext := []byte("Hello, I2P tunnel!")
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("ECIESEncryptor.Encrypt() failed: %v", err)
	}

	if len(ciphertext) < len(plaintext) {
		t.Error("Ciphertext should be longer than plaintext")
	}
}

func TestECIESRoundTrip_Simple(t *testing.T) {
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

	plaintext := []byte("Hello, I2P tunnel encryption!")

	// Encrypt
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("ECIESEncryptor.Encrypt() failed: %v", err)
	}

	// Decrypt
	decrypted, err := decryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("ECIESDecryptor.Decrypt() failed: %v", err)
	}

	// Verify round-trip
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Round-trip failed: got %v, want %v", decrypted, plaintext)
	}
}

func TestECIESFactory_Simple(t *testing.T) {
	// Generate test keys
	pubKey, _, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	var layerKey, ivKey TunnelKey
	copy(layerKey[:], pubKey[:])

	// Test ECIES factory creation
	encryptor, err := NewTunnelEncryptor(TunnelEncryptionECIES, layerKey, ivKey)
	if err != nil {
		t.Fatalf("NewTunnelEncryptor(ECIES) failed: %v", err)
	}

	if encryptor.Type() != TunnelEncryptionECIES {
		t.Errorf("Factory encryptor type = %v, want %v", encryptor.Type(), TunnelEncryptionECIES)
	}

	// Test encryption works
	plaintext := []byte("Test factory encryption")
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Factory encryptor.Encrypt() failed: %v", err)
	}

	if len(ciphertext) < len(plaintext) {
		t.Error("Factory encryption should produce longer ciphertext")
	}
}
