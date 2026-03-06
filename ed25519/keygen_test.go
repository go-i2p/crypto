package ed25519

import (
	"testing"
)

func TestGenerateEd25519KeyPair(t *testing.T) {
	pubKey, privKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair failed: %v", err)
	}

	t.Run("KeySizes", func(t *testing.T) {
		if pubKey == nil {
			t.Fatal("Public key is nil")
		}
		if privKey == nil {
			t.Fatal("Private key is nil")
		}
		if len(*pubKey) != 32 {
			t.Errorf("Public key size: expected 32, got %d", len(*pubKey))
		}
		if len(*privKey) != 64 {
			t.Errorf("Private key size: expected 64, got %d", len(*privKey))
		}
	})

	t.Run("SignVerifyRoundTrip", func(t *testing.T) {
		signer, err := privKey.NewSigner()
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		verifier, err := pubKey.NewVerifier()
		if err != nil {
			t.Fatalf("NewVerifier failed: %v", err)
		}
		message := []byte("test message")
		signature, err := signer.Sign(message)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if err := verifier.Verify(message, signature); err != nil {
			t.Errorf("Verify failed: %v", err)
		}
	})
}
