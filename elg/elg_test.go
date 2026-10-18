package elg

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/go-i2p/elgamal"
)

func BenchmarkElgGenerate(b *testing.B) {
	k := new(elgamal.PrivateKey)
	for n := 0; n < b.N; n++ {
		err := ElgamalGenerate(k, rand.Reader)
		if err != nil {
			panic(err.Error())
		}
	}
}

// setupElgBenchmark generates an ElGamal key pair and encrypter for benchmarks.
func setupElgBenchmark(b *testing.B) (*elgamal.PrivateKey, *ElgamalEncryption, []byte) {
	b.Helper()
	prv := new(elgamal.PrivateKey)
	err := ElgamalGenerate(prv, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	pub := createElgamalPublicKey(padElgBytes(prv.Y.Bytes()))
	enc, err := createElgamalEncryption(pub)
	if err != nil {
		b.Fatal(err)
	}
	d := make([]byte, 222)
	io.ReadFull(rand.Reader, d)
	return prv, enc, d
}

func BenchmarkElgDecrypt(b *testing.B) {
	prv, enc, d := setupElgBenchmark(b)
	c, _ := enc.Encrypt(d)
	fails := 0
	dec := &elgDecrypter{
		k: prv,
	}
	for n := 0; n < b.N; n++ {
		p, err := dec.Decrypt(c)
		if err != nil {
			fails++
		} else if !bytes.Equal(p, d) {
			fails++
		}
	}
	log.Debugf("%d fails %d rounds", fails, b.N)
}

func BenchmarkElgEncrypt(b *testing.B) {
	_, enc, d := setupElgBenchmark(b)
	fails := 0
	for n := 0; n < b.N; n++ {
		_, err := enc.Encrypt(d)
		if err != nil {
			fails++
		}
	}
	log.Debugf("%d fails %d rounds", fails, b.N)
}

func TestElg(t *testing.T) {
	k, err := generateElgamalPrivateKey(t)
	if err != nil {
		return
	}

	msg, err := generateRandomMessage(t)
	if err != nil {
		return
	}

	encrypter, err := createElgamalEncrypter(t, k)
	if err != nil {
		return
	}

	ciphertext, err := encryptMessage(t, encrypter, msg)
	if err != nil {
		return
	}

	decryptedMsg, err := decryptMessage(t, k, ciphertext)
	if err != nil {
		return
	}

	validateRoundTripResult(t, msg, decryptedMsg)
}

// generateElgamalPrivateKey creates a new ElGamal private key for testing.
func generateElgamalPrivateKey(t *testing.T) (*elgamal.PrivateKey, error) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Logf("error while generating key: %s", err.Error())
		t.Fail()
		return nil, err
	}
	return k, nil
}

// generateRandomMessage creates a random message of the appropriate size for ElGamal encryption.
func generateRandomMessage(t *testing.T) ([]byte, error) {
	msg := make([]byte, 222)
	_, err := io.ReadFull(rand.Reader, msg)
	if err != nil {
		t.Logf("failed to generate random message: %s", err.Error())
		t.Fail()
		return nil, err
	}
	return msg, nil
}

// padElgBytes right-aligns a big-endian big.Int value into the fixed 256-byte
// field the I2P ElGamal wire format requires. big.Int.Bytes() strips leading
// zeros, so passing it directly to createElgamalPublicKey intermittently yields
// a short slice (about 1 in 256 keys) and a nil public key.
func padElgBytes(v []byte) []byte {
	if len(v) == 256 {
		return v
	}
	padded := make([]byte, 256)
	if len(v) > 256 {
		return padded
	}
	copy(padded[256-len(v):], v)
	return padded
}

// createElgamalEncrypter sets up an ElGamal encrypter from the given private key.
func createElgamalEncrypter(t *testing.T, k *elgamal.PrivateKey) (*ElgamalEncryption, error) {
	pub := createElgamalPublicKey(padElgBytes(k.Y.Bytes()))
	enc, err := createElgamalEncryption(pub)
	if err != nil {
		t.Logf("failed to create encryption: %s", err.Error())
		t.Fail()
		return nil, err
	}
	return enc, nil
}

// encryptMessage encrypts the given message using the ElGamal encrypter.
func encryptMessage(t *testing.T, enc *ElgamalEncryption, msg []byte) ([]byte, error) {
	emsg, err := enc.Encrypt(msg)
	if err != nil {
		t.Logf("failed to encrypt message: %s", err.Error())
		t.Fail()
		return nil, err
	}
	return emsg, nil
}

// decryptMessage decrypts the given ciphertext using the ElGamal private key.
func decryptMessage(t *testing.T, k *elgamal.PrivateKey, ciphertext []byte) ([]byte, error) {
	dec, err := elgamalDecrypt(k, ciphertext, true)
	if err != nil {
		t.Logf("decrypt failed: %s", err.Error())
		t.Fail()
		return nil, err
	}
	return dec, nil
}

// validateRoundTripResult verifies that the decrypted message matches the original.
func validateRoundTripResult(t *testing.T, original, decrypted []byte) {
	if bytes.Equal(decrypted, original) {
		t.Logf("%q == %q", decrypted, original)
	} else {
		t.Logf("%q != %q", decrypted, original)
		t.Fail()
	}
}

func TestElgamalKeyValidation(t *testing.T) {
	// Test cases for createElgamalPrivateKey validation
	testCases := []struct {
		name        string
		keyData     []byte
		shouldError bool
	}{
		{
			name:        "Valid key length",
			keyData:     make([]byte, 256),
			shouldError: false,
		},
		{
			name:        "Invalid key length - too short",
			keyData:     make([]byte, 255),
			shouldError: true,
		},
		{
			name:        "Invalid key length - too long",
			keyData:     make([]byte, 257),
			shouldError: true,
		},
		{
			name:        "Zero key - invalid",
			keyData:     make([]byte, 256), // all zeros
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "Valid key length" {
				// Create a valid non-zero key for this test
				tc.keyData[255] = 1 // Set to 1 to make it valid
			}

			var elgKey ElgPrivateKey
			copy(elgKey[:], tc.keyData)

			_, err := elgKey.NewDecrypter()

			if tc.shouldError && err == nil {
				t.Errorf("Expected error for %s but got none", tc.name)
			} else if !tc.shouldError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}

// TestElgamalPayloadLengths is a regression test for the ElGamal message
// format. The payload length must be recovered from the structure of the
// decrypted block ([nonzero marker][SHA-256][data]) rather than by trimming
// trailing zeros, and the marker must not be required to equal 0xFF (the I2P
// low-level cryptography spec makes it a random nonzero byte since 0.9.28).
//
// The old implementation required m[0] == 0xFF, demanded exactly 255 bytes, and
// zero-trimmed the payload, which corrupted any plaintext ending in 0x00 and
// rejected short plaintexts.
func TestElgamalPayloadLengths(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	enc, err := pub.NewEncrypter()
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	dec, err := priv.NewDecrypter()
	if err != nil {
		t.Fatalf("NewDecrypter: %v", err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"single byte", []byte{0x41}},
		{"short", []byte("i2p")},
		{"trailing zero bytes", append([]byte("payload"), 0x00, 0x00, 0x00)},
		{"all zeros", make([]byte, 8)},
		{"full 222", func() []byte {
			b := make([]byte, 222)
			if _, err := io.ReadFull(rand.Reader, b); err != nil {
				t.Fatal(err)
			}
			return b
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := enc.Encrypt(tc.data)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if len(ct) != 514 {
				t.Fatalf("ciphertext length = %d, want 514", len(ct))
			}
			pt, err := dec.Decrypt(ct)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, tc.data) {
				t.Errorf("round trip mismatch: got %d bytes, want %d bytes", len(pt), len(tc.data))
			}
		})
	}
}
