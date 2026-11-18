package red25519

import (
	"testing"
)

// FuzzRed25519Verify drives RedDSA verification, whose decodePoint step parses
// attacker-controlled Edwards-curve points from the signature's R component.
// That decoding is the prime panic surface, so the target feeds arbitrary
// 64-byte signatures against a fixed valid public key and asserts verification
// returns a boolean result (via error) rather than panicking. It also confirms a
// genuine signature verifies.
func FuzzRed25519Verify(f *testing.F) {
	pub, priv, err := GenerateRed25519KeyPair()
	if err != nil {
		f.Fatalf("GenerateRed25519KeyPair: %v", err)
	}
	signer, err := priv.NewSigner()
	if err != nil {
		f.Fatalf("NewSigner: %v", err)
	}
	verifier, err := pub.NewVerifier()
	if err != nil {
		f.Fatalf("NewVerifier: %v", err)
	}

	f.Add([]byte("reddsa message"), make([]byte, SignatureSize))
	f.Add([]byte{}, make([]byte, SignatureSize))
	f.Add([]byte("x"), []byte("short sig"))

	f.Fuzz(func(t *testing.T, message, sig []byte) {
		// Genuine signature must verify.
		good, err := signer.Sign(message)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := verifier.Verify(message, good); err != nil {
			t.Fatalf("genuine Red25519 signature failed to verify: %v", err)
		}

		// Attacker-controlled signature: must error or verify, never panic.
		_ = verifier.Verify(message, sig)
		_ = verifier.VerifyHash(message, sig)
	})
}
