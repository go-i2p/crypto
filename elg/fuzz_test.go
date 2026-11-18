package elg

import (
	"bytes"
	"testing"

	"github.com/go-i2p/crypto/types"
)

// newTestKeyPair builds a fresh ElGamal key pair plus a decrypter. ElGamal
// keygen is expensive (2048-bit), so fuzz targets generate the key once outside
// the fuzz closure and reuse it across iterations.
func newTestKeyPair(f *testing.F) (types.Encrypter, types.Decrypter) {
	f.Helper()
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		f.Fatalf("GenerateKeyPair: %v", err)
	}
	enc, err := pub.NewEncrypter()
	if err != nil {
		f.Fatalf("NewEncrypter: %v", err)
	}
	dec, err := priv.NewDecrypter()
	if err != nil {
		f.Fatalf("NewDecrypter: %v", err)
	}
	return enc, dec
}

// FuzzElgDecrypt drives ElGamal decryption with arbitrary ciphertext. The
// decrypter must reject malformed input (wrong length, bad padding, failed
// integrity hash) with an error and never panic, since ciphertext arrives from
// the untrusted network.
func FuzzElgDecrypt(f *testing.F) {
	_, dec := newTestKeyPair(f)

	f.Add(make([]byte, 514))
	f.Add([]byte("short"))
	f.Add(make([]byte, 513))
	f.Add(append(bytes.Repeat([]byte{0xAB}, 512), 0x00, 0x00))

	f.Fuzz(func(t *testing.T, ct []byte) {
		// Any result is acceptable; the contract is "no panic, error on garbage".
		_, _ = dec.Decrypt(ct)
	})
}

// FuzzElgRoundTrip encrypts arbitrary (length-bounded) plaintext under a fixed
// key and requires the decrypter to recover it exactly. It also exercises the
// >222-byte rejection path.
func FuzzElgRoundTrip(f *testing.F) {
	enc, dec := newTestKeyPair(f)

	f.Add([]byte("elgamal payload"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x42}, 222))
	f.Add(bytes.Repeat([]byte{0x42}, 223))

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			// Only the documented oversize limit may error.
			if len(plaintext) <= 222 {
				t.Fatalf("unexpected Encrypt error for %d bytes: %v", len(plaintext), err)
			}
			return
		}
		got, err := dec.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt of own ciphertext: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("elgamal round-trip mismatch")
		}
	})
}
