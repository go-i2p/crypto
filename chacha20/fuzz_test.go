package chacha20

import (
	"bytes"
	"testing"
)

// FuzzStream exercises the unauthenticated ChaCha20 stream cipher (I2P STREAM)
// with arbitrary key/IV/plaintext. It asserts the documented length checks hold,
// the cipher never panics, and that encryption is its own inverse (the property
// that makes StreamDecrypt an alias of StreamEncrypt).
func FuzzStream(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 12), []byte("stream plaintext"))
	f.Add(make([]byte, 32), make([]byte, 12), []byte{})
	f.Add(make([]byte, 31), make([]byte, 12), []byte("bad key len"))
	f.Add(make([]byte, 32), make([]byte, 11), []byte("bad iv len"))

	f.Fuzz(func(t *testing.T, key, iv, plaintext []byte) {
		ct, err := StreamEncrypt(key, iv, plaintext)
		if err != nil {
			// Only documented length mismatches may error.
			if len(key) == KeySize && len(iv) == NonceSize {
				t.Fatalf("unexpected error for valid sizes: %v", err)
			}
			return
		}
		if len(ct) != len(plaintext) {
			t.Fatalf("ciphertext length %d != plaintext length %d", len(ct), len(plaintext))
		}
		// Stream cipher: decrypting the ciphertext must recover the plaintext.
		back, err := StreamDecrypt(key, iv, ct)
		if err != nil {
			t.Fatalf("StreamDecrypt: %v", err)
		}
		if !bytes.Equal(back, plaintext) {
			t.Fatalf("stream round-trip mismatch")
		}
	})
}
