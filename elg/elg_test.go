package elg

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

// createElgamalEncrypter sets up an ElGamal encrypter from the given private key.
func createElgamalEncrypter(t *testing.T, k *elgamal.PrivateKey) (*ElgamalEncryption, error) {
	pub := createElgamalPublicKey(k.Y.Bytes())
	enc, err := createElgamalEncryption(pub, rand.Reader)
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
