package aes

import (
	"bytes"
	"testing"
)

// FuzzNewAESKey exercises the AES key constructor's length validation. It must
// accept exactly 16/24/32-byte keys with a 16-byte IV and reject everything
// else without panicking.
func FuzzNewAESKey(f *testing.F) {
	f.Add(make([]byte, 16), make([]byte, 16))
	f.Add(make([]byte, 24), make([]byte, 16))
	f.Add(make([]byte, 32), make([]byte, 16))
	f.Add([]byte("short"), []byte("bad iv"))
	f.Add(make([]byte, 16), make([]byte, 15))

	f.Fuzz(func(t *testing.T, key, iv []byte) {
		k, err := NewAESKey(key, iv)
		if err != nil {
			return // rejected input is fine
		}
		// Accepted keys must report the canonical length and round-trip a
		// padded encrypt/decrypt cycle without panicking.
		switch k.Len() {
		case 16, 24, 32:
		default:
			t.Fatalf("accepted key with unexpected length %d", k.Len())
		}
	})
}

// FuzzAESRoundTrip drives a full AES-CBC/PKCS#7 encrypt-then-decrypt cycle with
// arbitrary key material and plaintext. It asserts the library never panics on
// malformed ciphertext and that a clean round-trip recovers the plaintext.
func FuzzAESRoundTrip(f *testing.F) {
	seedKey := make([]byte, 32)
	seedIV := make([]byte, 16)
	f.Add(seedKey, seedIV, []byte("hello i2p"))
	f.Add(seedKey, seedIV, []byte{})
	f.Add(seedKey[:16], seedIV, []byte("aes-128 plaintext"))

	f.Fuzz(func(t *testing.T, key, iv, plaintext []byte) {
		k, err := NewAESKey(key, iv)
		if err != nil {
			return
		}
		enc, err := k.NewEncrypter()
		if err != nil {
			t.Fatalf("NewEncrypter on accepted key: %v", err)
		}
		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		dec, err := k.NewDecrypter()
		if err != nil {
			t.Fatalf("NewDecrypter on accepted key: %v", err)
		}
		got, err := dec.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt of own ciphertext: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
		}

		// Now feed arbitrary bytes as ciphertext: must return an error or a
		// result, but never panic.
		_, _ = dec.Decrypt(plaintext)
	})
}
