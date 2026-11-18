package ed25519

import (
	"bytes"
	"testing"
)

// FuzzEd25519SignVerify drives Ed25519 signing and verification. It checks that
// a genuine signature always verifies, and that arbitrary attacker-controlled
// signatures (and messages) fail verification without panicking.
func FuzzEd25519SignVerify(f *testing.F) {
	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		f.Fatalf("GenerateEd25519KeyPair: %v", err)
	}
	signer, err := priv.NewSigner()
	if err != nil {
		f.Fatalf("NewSigner: %v", err)
	}
	verifier, err := pub.NewVerifier()
	if err != nil {
		f.Fatalf("NewVerifier: %v", err)
	}

	f.Add([]byte("message to sign"), make([]byte, 64))
	f.Add([]byte{}, []byte{})
	f.Add([]byte("another message"), bytes.Repeat([]byte{0x01}, 64))

	f.Fuzz(func(t *testing.T, message, sig []byte) {
		// A freshly produced signature must verify.
		good, err := signer.Sign(message)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := verifier.Verify(message, good); err != nil {
			t.Fatalf("genuine signature failed to verify: %v", err)
		}

		// Attacker-controlled signature over the message: must error or verify,
		// never panic.
		_ = verifier.Verify(message, sig)

		// Attacker-controlled signature over the message via VerifyHash path.
		_ = verifier.VerifyHash(message, sig)
	})
}
