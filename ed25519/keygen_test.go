package ed25519

import (
	"testing"
)

func TestGenerateEd25519KeyPair(t *testing.T) {
	pubKey, privKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair failed: %v", err)
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

	if len(*privKey) != 64 {
		t.Errorf("Private key size: expected 64, got %d", len(*privKey))
	}

	// Verify can create signer
	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Verify can create verifier
	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	// Test signing and verification
	message := []byte("test message")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	err = verifier.Verify(message, signature)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}
