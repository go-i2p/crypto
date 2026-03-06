package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-i2p/crypto/types"
)

// assertRSAConstructorValidation is a test helper that validates an RSA key constructor
// rejects invalid sizes, nil, empty, and all-zero inputs.
func assertRSAConstructorValidation(t *testing.T, name string, constructor func([]byte) (interface{}, error), validSize int, rejectsZero bool) {
	t.Helper()

	// Create valid key with non-zero data
	validData := make([]byte, validSize)
	for i := range validData {
		validData[i] = byte(i%255 + 1)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"valid key", validData, false},
		{"too short", make([]byte, validSize-1), true},
		{"too long", make([]byte, validSize+1), true},
		{"nil data", nil, true},
		{"empty slice", []byte{}, true},
	}
	if rejectsZero {
		tests = append(tests, struct {
			name    string
			data    []byte
			wantErr bool
		}{"all zeros", make([]byte, validSize), true})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := constructor(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("%s() error = %v, wantErr %v", name, err, tt.wantErr)
				return
			}
			if !tt.wantErr && key == nil {
				t.Errorf("%s() returned nil key", name)
			}
		})
	}
}

// TestRSAConstructorValidation tests all RSA key constructors with a common validation pattern.
func TestRSAConstructorValidation(t *testing.T) {
	constructors := []struct {
		name        string
		constructor func([]byte) (interface{}, error)
		validSize   int
		rejectsZero bool
	}{
		{"NewRSA2048PrivateKey", func(b []byte) (interface{}, error) { return NewRSA2048PrivateKey(b) }, 512, true},
		{"NewRSA2048PublicKey", func(b []byte) (interface{}, error) { return NewRSA2048PublicKey(b) }, 256, true},
		{"NewRSA3072PrivateKey", func(b []byte) (interface{}, error) { return NewRSA3072PrivateKey(b) }, 768, true},
		{"NewRSA3072PublicKey", func(b []byte) (interface{}, error) { return NewRSA3072PublicKey(b) }, 384, true},
		{"NewRSA4096PrivateKey", func(b []byte) (interface{}, error) { return NewRSA4096PrivateKey(b) }, 1024, true},
		{"NewRSA4096PublicKey", func(b []byte) (interface{}, error) { return NewRSA4096PublicKey(b) }, 512, true},
	}

	for _, ctor := range constructors {
		t.Run(ctor.name, func(t *testing.T) {
			assertRSAConstructorValidation(t, ctor.name, ctor.constructor, ctor.validSize, ctor.rejectsZero)
		})
	}
}

// TestRSAConstructorDefensiveCopy tests that constructors make defensive copies
func TestRSAConstructorDefensiveCopy(t *testing.T) {
	t.Run("RSA2048PrivateKey", func(t *testing.T) {
		data := make([]byte, 512)
		for i := range data {
			data[i] = byte(i % 256)
		}
		original := make([]byte, len(data))
		copy(original, data)

		key, err := NewRSA2048PrivateKey(data)
		if err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}

		// Modify original data
		data[0] = 0xFF

		// Key should not be affected
		if bytes.Equal(key.Bytes(), data) {
			t.Error("Constructor did not make defensive copy")
		}
		if !bytes.Equal(key.Bytes(), original) {
			t.Error("Key was modified when input was modified")
		}
	})

	t.Run("RSA2048PublicKey", func(t *testing.T) {
		data := make([]byte, 256)
		for i := range data {
			data[i] = byte(i % 256)
		}
		original := make([]byte, len(data))
		copy(original, data)

		key, err := NewRSA2048PublicKey(data)
		if err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}

		// Modify original data
		data[0] = 0xFF

		// Key should not be affected
		if bytes.Equal(key.Bytes(), data) {
			t.Error("Constructor did not make defensive copy")
		}
		if !bytes.Equal(key.Bytes(), original) {
			t.Error("Key was modified when input was modified")
		}
	})
}

// Test helper function to generate RSA keys for testing
func generateRSA2048KeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func generateRSA3072KeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 3072)
}

func generateRSA4096KeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

// Generate a proper RSA2048PrivateKey
func generateRSA2048PrivateKey() (RSA2048PrivateKey, error) {
	stdPrivKey, err := generateRSA2048KeyPair()
	if err != nil {
		return RSA2048PrivateKey{}, err
	}

	// I2P-compliant format: Store modulus (256 bytes) + private exponent (256 bytes)
	var privKey RSA2048PrivateKey

	// Store the modulus (N) - first 256 bytes
	modulusBytes := stdPrivKey.N.Bytes()
	if len(modulusBytes) > 256 {
		return RSA2048PrivateKey{}, ErrInvalidKeySize
	}
	// Pad with leading zeros if needed
	copy(privKey.RSA2048PrivateKey[256-len(modulusBytes):256], modulusBytes)

	// Store the private exponent (D) - next 256 bytes
	dBytes := stdPrivKey.D.Bytes()
	if len(dBytes) > 256 {
		return RSA2048PrivateKey{}, ErrInvalidKeySize
	}
	// Pad with leading zeros if needed
	copy(privKey.RSA2048PrivateKey[512-len(dBytes):512], dBytes)

	return privKey, nil
}

// Generate a proper RSA3072PrivateKey
func generateRSA3072PrivateKey() (RSA3072PrivateKey, error) {
	stdPrivKey, err := generateRSA3072KeyPair()
	if err != nil {
		return RSA3072PrivateKey{}, err
	}

	// I2P-compliant format: Store modulus (384 bytes) + private exponent (384 bytes)
	var privKey RSA3072PrivateKey

	// Store the modulus (N) - first 384 bytes
	modulusBytes := stdPrivKey.N.Bytes()
	if len(modulusBytes) > 384 {
		return RSA3072PrivateKey{}, ErrInvalidKeySize
	}
	// Pad with leading zeros if needed
	copy(privKey.RSA3072PrivateKey[384-len(modulusBytes):384], modulusBytes)

	// Store the private exponent (D) - next 384 bytes
	dBytes := stdPrivKey.D.Bytes()
	if len(dBytes) > 384 {
		return RSA3072PrivateKey{}, ErrInvalidKeySize
	}
	// Pad with leading zeros if needed
	copy(privKey.RSA3072PrivateKey[768-len(dBytes):768], dBytes)

	return privKey, nil
}

// Generate a proper RSA4096PrivateKey
func generateRSA4096PrivateKey() (RSA4096PrivateKey, error) {
	stdPrivKey, err := generateRSA4096KeyPair()
	if err != nil {
		return RSA4096PrivateKey{}, err
	}

	// I2P-compliant format: Store modulus (512 bytes) + private exponent (512 bytes)
	var privKey RSA4096PrivateKey

	// Store the modulus (N) - first 512 bytes
	modulusBytes := stdPrivKey.N.Bytes()
	if len(modulusBytes) > 512 {
		return RSA4096PrivateKey{}, ErrInvalidKeySize
	}
	// Pad with leading zeros if needed
	copy(privKey.RSA4096PrivateKey[512-len(modulusBytes):512], modulusBytes)

	// Store the private exponent (D) - next 512 bytes
	dBytes := stdPrivKey.D.Bytes()
	if len(dBytes) > 512 {
		return RSA4096PrivateKey{}, ErrInvalidKeySize
	}
	// Pad with leading zeros if needed
	copy(privKey.RSA4096PrivateKey[1024-len(dBytes):1024], dBytes)

	return privKey, nil
}

// testRSASignAndVerify is a test helper that validates sign-and-verify round-trip
// for any RSA key size. It generates a key pair, signs test data, and verifies the signature.
func testRSASignAndVerify(t *testing.T, genKey func() (types.Signer, types.SigningPublicKey, error), label string) {
	t.Helper()

	signer, pubKey, err := genKey()
	if err != nil {
		t.Fatalf("failed to generate %s key: %v", label, err)
	}

	testData := []byte("Hello, " + label + "!")

	signature, err := signer.Sign(testData)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	err = verifier.Verify(testData, signature)
	if err != nil {
		t.Fatalf("failed to verify signature: %v", err)
	}
}

func TestRSA_SignAndVerify(t *testing.T) {
	tests := []struct {
		name   string
		genKey func() (types.Signer, types.SigningPublicKey, error)
	}{
		{
			name: "RSA2048",
			genKey: func() (types.Signer, types.SigningPublicKey, error) {
				priv, err := generateRSA2048PrivateKey()
				if err != nil {
					return nil, nil, err
				}
				pub, err := priv.Public()
				return priv, pub, err
			},
		},
		{
			name: "RSA3072",
			genKey: func() (types.Signer, types.SigningPublicKey, error) {
				priv, err := generateRSA3072PrivateKey()
				if err != nil {
					return nil, nil, err
				}
				pub, err := priv.Public()
				return priv, pub, err
			},
		},
		{
			name: "RSA4096",
			genKey: func() (types.Signer, types.SigningPublicKey, error) {
				priv, err := generateRSA4096PrivateKey()
				if err != nil {
					return nil, nil, err
				}
				pub, err := priv.Public()
				return priv, pub, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testRSASignAndVerify(t, tt.genKey, tt.name)
		})
	}
}

func TestRSA2048_SignHashAndVerifyHash(t *testing.T) {
	// Generate a proper RSA2048 key pair
	privKey, err := generateRSA2048PrivateKey()
	if err != nil {
		t.Fatalf("failed to generate RSA2048 key: %v", err)
	}

	// Get the public key
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("failed to extract public key: %v", err)
	}

	// Test hash (SHA-256)
	testHash := make([]byte, 32)
	for i := range testHash {
		testHash[i] = byte(i)
	}

	// Sign the hash
	signature, err := privKey.SignHash(testHash)
	if err != nil {
		t.Fatalf("failed to sign hash: %v", err)
	}

	// Verify the signature
	if rsaPub, ok := pubKey.(RSA2048PublicKey); ok {
		err = rsaPub.VerifyHash(testHash, signature)
		if err != nil {
			t.Fatalf("failed to verify hash signature: %v", err)
		}
	} else {
		t.Fatalf("unexpected public key type: %T", pubKey)
	}
}

func TestRSA2048_PublicKeyExtraction(t *testing.T) {
	// Generate a proper RSA2048 key pair
	privKey, err := generateRSA2048PrivateKey()
	if err != nil {
		t.Fatalf("failed to generate RSA2048 key: %v", err)
	}

	// Extract public key
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("failed to extract public key: %v", err)
	}

	// Verify it's the correct type
	if _, ok := pubKey.(RSA2048PublicKey); !ok {
		t.Fatalf("unexpected public key type: %T", pubKey)
	}

	// Verify the public key has the correct length
	if pubKey.Len() != 256 {
		t.Errorf("RSA2048PublicKey.Len() = %d, want 256", pubKey.Len())
	}
}

func TestRSA2048_KeyInterfaces(t *testing.T) {
	// Test interface compliance without key generation
	var privKey RSA2048PrivateKey
	var pubKey RSA2048PublicKey

	// Test private key interfaces (use pointer for PrivateKey due to Zero method)
	var _ types.PrivateKey = (*RSA2048PrivateKey)(nil)
	var _ types.Signer = privKey

	// Test public key interfaces
	var _ types.PublicKey = pubKey
	var _ types.Verifier = pubKey
}

func TestRSA2048_Bytes(t *testing.T) {
	var privKey RSA2048PrivateKey
	var pubKey RSA2048PublicKey

	// Test private key bytes (I2P format: 256 bytes modulus + 256 bytes private exponent)
	privBytes := privKey.Bytes()
	if len(privBytes) != 512 {
		t.Errorf("RSA2048PrivateKey.Bytes() length = %d, want 512", len(privBytes))
	}

	// Test public key bytes
	pubBytes := pubKey.Bytes()
	if len(pubBytes) != 256 {
		t.Errorf("RSA2048PublicKey.Bytes() length = %d, want 256", len(pubBytes))
	}

	// Test public key len
	if pubKey.Len() != 256 {
		t.Errorf("RSA2048PublicKey.Len() = %d, want 256", pubKey.Len())
	}
}

func TestRSA2048_Zero(t *testing.T) {
	var privKey RSA2048PrivateKey

	// Fill with test data
	for i := range privKey.RSA2048PrivateKey {
		privKey.RSA2048PrivateKey[i] = byte(i % 256)
	}

	// Zero the key (use pointer receiver)
	(&privKey).Zero()

	// Verify key is zeroed
	zeroedBytes := privKey.Bytes()
	for i, b := range zeroedBytes {
		if b != 0 {
			t.Errorf("RSA2048PrivateKey.Zero() failed: byte %d is %d, want 0", i, b)
		}
	}
}

func TestRSA2048_NewVerifier(t *testing.T) {
	var pubKey RSA2048PublicKey

	// Create verifier
	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Errorf("RSA2048PublicKey.NewVerifier() error = %v", err)
		return
	}

	if verifier == nil {
		t.Error("RSA2048PublicKey.NewVerifier() returned nil")
	}

	// Verify it implements the interface
	var _ types.Verifier = verifier
}

func TestRSA2048_InvalidSignature(t *testing.T) {
	// Generate a proper RSA2048 key pair
	privKey, err := generateRSA2048PrivateKey()
	if err != nil {
		t.Fatalf("failed to generate RSA2048 key: %v", err)
	}

	// Get the public key
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("failed to extract public key: %v", err)
	}

	// Test data
	testData := []byte("Hello, RSA2048!")

	// Create invalid signature
	invalidSig := make([]byte, 256)
	for i := range invalidSig {
		invalidSig[i] = byte(i)
	}

	// Verify the invalid signature should fail
	if rsaPub, ok := pubKey.(RSA2048PublicKey); ok {
		err = rsaPub.Verify(testData, invalidSig)
		if err == nil {
			t.Error("RSA2048PublicKey.Verify() should fail with invalid signature")
		}
	} else {
		t.Fatalf("unexpected public key type: %T", pubKey)
	}
}

func TestRSA2048_InvalidHashLength(t *testing.T) {
	var pubKey RSA2048PublicKey

	// Test with wrong hash length
	wrongHash := []byte("wrong length hash")
	dummySig := make([]byte, 256)

	err := pubKey.VerifyHash(wrongHash, dummySig)
	if err == nil {
		t.Error("RSA2048PublicKey.VerifyHash() should fail with wrong hash length")
	}
}

// TestRSA3072_SignAndVerify and TestRSA4096_SignAndVerify consolidated
// into table-driven TestRSA_SignAndVerify above.

// Test utility functions
func TestRSAPublicKeyFromBytes(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		expectedSize int
		wantErr      bool
	}{
		{
			name:         "valid RSA2048 key",
			data:         make([]byte, 256),
			expectedSize: 256,
			wantErr:      false,
		},
		{
			name:         "valid RSA3072 key",
			data:         make([]byte, 384),
			expectedSize: 384,
			wantErr:      false,
		},
		{
			name:         "valid RSA4096 key",
			data:         make([]byte, 512),
			expectedSize: 512,
			wantErr:      false,
		},
		{
			name:         "invalid size",
			data:         make([]byte, 100),
			expectedSize: 256,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill with non-zero data
			for i := range tt.data {
				tt.data[i] = byte(i % 256)
			}

			pubKey, err := rsaPublicKeyFromBytes(tt.data, tt.expectedSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("rsaPublicKeyFromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if pubKey == nil {
					t.Error("rsaPublicKeyFromBytes() returned nil key")
				}
				if pubKey.E != 65537 {
					t.Errorf("rsaPublicKeyFromBytes() exponent = %d, want 65537", pubKey.E)
				}
			}
		})
	}
}

// Benchmark tests
func BenchmarkRSA2048_Sign(b *testing.B) {
	privKey, err := generateRSA2048PrivateKey()
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("benchmark data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := privKey.Sign(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRSA2048_Verify(b *testing.B) {
	privKey, err := generateRSA2048PrivateKey()
	if err != nil {
		b.Fatal(err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("benchmark data")
	sig, err := privKey.Sign(data)
	if err != nil {
		b.Fatal(err)
	}

	rsaPub, ok := pubKey.(RSA2048PublicKey)
	if !ok {
		b.Fatalf("unexpected public key type: %T", pubKey)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := rsaPub.Verify(data, sig)
		if err != nil {
			b.Fatal(err)
		}
	}
}
