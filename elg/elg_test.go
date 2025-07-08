package elgamal

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/openpgp/elgamal"
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

func BenchmarkElgDecrypt(b *testing.B) {
	prv := new(elgamal.PrivateKey)
	err := ElgamalGenerate(prv, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	pub := createElgamalPublicKey(prv.Y.Bytes())
	enc, err := createElgamalEncryption(pub, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	d := make([]byte, 222)
	_, _ = io.ReadFull(rand.Reader, d)
	c, err := enc.Encrypt(d)
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
	prv := new(elgamal.PrivateKey)
	err := ElgamalGenerate(prv, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	pub := createElgamalPublicKey(prv.Y.Bytes())
	enc, err := createElgamalEncryption(pub, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	d := make([]byte, 222)
	_, err = io.ReadFull(rand.Reader, d)
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
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err == nil {
		msg := make([]byte, 222)
		_, err := io.ReadFull(rand.Reader, msg)
		if err == nil {
			pub := createElgamalPublicKey(k.Y.Bytes())
			enc, err := createElgamalEncryption(pub, rand.Reader)
			if err == nil {
				emsg, err := enc.Encrypt(msg)
				if err == nil {
					dec, err := elgamalDecrypt(k, emsg, true)
					if err == nil {
						if bytes.Equal(dec, msg) {
							t.Logf("%q == %q", dec, msg)
						} else {
							t.Logf("%q != %q", dec, msg)
							t.Fail()
						}
					} else {
						t.Logf("decrypt failed: %s", err.Error())
						t.Fail()
					}
				} else {
					t.Logf("failed to encrypt message: %s", err.Error())
					t.Fail()
				}
			} else {
				t.Logf("failed to create encryption: %s", err.Error())
				t.Fail()
			}
		} else {
			t.Logf("failed to generate random message: %s", err.Error())
			t.Fail()
		}
	} else {
		t.Logf("error while generating key: %s", err.Error())
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
