package ecies

import (
	"bytes"
	"testing"
)

// FuzzECIESX25519 exercises the one-time ECIES-X25519 seal/open path with a
// fixed recipient key pair. It checks that a clean round-trip recovers the
// plaintext for arbitrary input, and that arbitrary attacker-controlled
// ciphertext fails to decrypt without panicking.
func FuzzECIESX25519(f *testing.F) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		f.Fatalf("GenerateKeyPair: %v", err)
	}

	f.Add([]byte("ecies one-time payload"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x11}, 1000))

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		ct, err := EncryptECIESX25519(pub, plaintext)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		got, err := DecryptECIESX25519(priv, ct)
		if err != nil {
			t.Fatalf("Decrypt of own ciphertext: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("ECIES round-trip mismatch")
		}

		// Attacker-controlled ciphertext (reuse the plaintext bytes as a frame):
		// must return an error or a result, but never panic.
		_, _ = DecryptECIESX25519(priv, plaintext)
	})
}
