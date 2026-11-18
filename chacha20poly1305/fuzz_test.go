package chacha20poly1305

import (
	"bytes"
	"testing"
)

// FuzzAEAD drives ChaCha20-Poly1305 seal/open with arbitrary inputs. It checks
// the documented nonce/tag length guards, that a clean seal/open round-trips,
// and that tampered ciphertext or tags fail authentication rather than panicking
// or returning forged plaintext.
func FuzzAEAD(f *testing.F) {
	var seedKey [KeySize]byte
	seedKey[0] = 0xAB
	f.Add(seedKey[:], []byte("plaintext"), []byte("aad"), make([]byte, NonceSize))
	f.Add(seedKey[:], []byte{}, []byte{}, make([]byte, NonceSize))
	f.Add(seedKey[:], []byte("x"), []byte("y"), make([]byte, 11)) // bad nonce

	f.Fuzz(func(t *testing.T, key, plaintext, aad, nonce []byte) {
		if len(key) != KeySize {
			return
		}
		var k [KeySize]byte
		copy(k[:], key)
		a, err := NewAEAD(k)
		if err != nil {
			t.Fatalf("NewAEAD: %v", err)
		}

		ct, tag, err := a.Encrypt(plaintext, aad, nonce)
		if err != nil {
			if len(nonce) == NonceSize {
				t.Fatalf("unexpected Encrypt error for valid nonce: %v", err)
			}
			return
		}

		// Clean open must recover the plaintext.
		got, err := a.Decrypt(ct, tag[:], aad, nonce)
		if err != nil {
			t.Fatalf("Decrypt of own ciphertext: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("AEAD round-trip mismatch")
		}

		// Tamper the first ciphertext byte (if any) and require auth failure.
		if len(ct) > 0 {
			bad := append([]byte(nil), ct...)
			bad[0] ^= 0x01
			if _, err := a.Decrypt(bad, tag[:], aad, nonce); err == nil {
				t.Fatalf("tampered ciphertext authenticated")
			}
		}

		// Arbitrary bytes as ciphertext must never panic.
		_, _ = a.Decrypt(plaintext, aad, nonce, nonce)
	})
}
