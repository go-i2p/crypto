package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/go-i2p/crypto/types"
)

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

	// TEMPORARY FIX: Store only the modulus bytes for now
	// This is not the final I2P-compliant format, but allows testing
	var privKey RSA2048PrivateKey
	
	// Store the modulus (N) which is exactly 256 bytes for RSA-2048
	modulusBytes := stdPrivKey.N.Bytes()
	if len(modulusBytes) != 256 {
		// Pad with leading zeros if needed
		if len(modulusBytes) < 256 {
			paddedModulus := make([]byte, 256)
			copy(paddedModulus[256-len(modulusBytes):], modulusBytes)
			copy(privKey.RSA2048PrivateKey[:], paddedModulus)
		} else {
			return RSA2048PrivateKey{}, ErrInvalidKeySize
		}
	} else {
		copy(privKey.RSA2048PrivateKey[:], modulusBytes)
	}

	return privKey, nil
}

// Generate a proper RSA3072PrivateKey
func generateRSA3072PrivateKey() (RSA3072PrivateKey, error) {
	stdPrivKey, err := generateRSA3072KeyPair()
	if err != nil {
		return RSA3072PrivateKey{}, err
	}

	// Convert to PKCS#1 DER format
	derBytes := x509.MarshalPKCS1PrivateKey(stdPrivKey)

	var privKey RSA3072PrivateKey
	if len(derBytes) > 786 {
		return RSA3072PrivateKey{}, ErrInvalidKeySize
	}

	// Copy the DER bytes to the fixed-size array
	copy(privKey.RSA3072PrivateKey[:], derBytes)

	return privKey, nil
}

// Generate a proper RSA4096PrivateKey
func generateRSA4096PrivateKey() (RSA4096PrivateKey, error) {
	stdPrivKey, err := generateRSA4096KeyPair()
	if err != nil {
		return RSA4096PrivateKey{}, err
	}

	// Convert to PKCS#1 DER format
	derBytes := x509.MarshalPKCS1PrivateKey(stdPrivKey)

	var privKey RSA4096PrivateKey
	if len(derBytes) > 1024 {
		return RSA4096PrivateKey{}, ErrInvalidKeySize
	}

	// Copy the DER bytes to the fixed-size array
	copy(privKey.RSA4096PrivateKey[:], derBytes)

	return privKey, nil
}

// Test RSA2048 implementation
func TestRSA2048_SignAndVerify(t *testing.T) {
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

	// Sign the data
	signature, err := privKey.Sign(testData)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	// Verify the signature
	if rsaPub, ok := pubKey.(RSA2048PublicKey); ok {
		err = rsaPub.Verify(testData, signature)
		if err != nil {
			t.Fatalf("failed to verify signature: %v", err)
		}
	} else {
		t.Fatalf("unexpected public key type: %T", pubKey)
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

	// Test private key bytes
	privBytes := privKey.Bytes()
	if len(privBytes) != 256 {
		t.Errorf("RSA2048PrivateKey.Bytes() length = %d, want 256", len(privBytes))
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

// Test RSA3072 implementation
func TestRSA3072_SignAndVerify(t *testing.T) {
	// Generate a proper RSA3072 key pair
	privKey, err := generateRSA3072PrivateKey()
	if err != nil {
		t.Fatalf("failed to generate RSA3072 key: %v", err)
	}

	// Get the public key
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("failed to extract public key: %v", err)
	}

	// Test data
	testData := []byte("Hello, RSA3072!")

	// Sign the data
	signature, err := privKey.Sign(testData)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	// Verify the signature
	if rsaPub, ok := pubKey.(RSA3072PublicKey); ok {
		err = rsaPub.Verify(testData, signature)
		if err != nil {
			t.Fatalf("failed to verify signature: %v", err)
		}
	} else {
		t.Fatalf("unexpected public key type: %T", pubKey)
	}
}

// Test RSA4096 implementation
func TestRSA4096_SignAndVerify(t *testing.T) {
	// Generate a proper RSA4096 key pair
	privKey, err := generateRSA4096PrivateKey()
	if err != nil {
		t.Fatalf("failed to generate RSA4096 key: %v", err)
	}

	// Get the public key
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("failed to extract public key: %v", err)
	}

	// Test data
	testData := []byte("Hello, RSA4096!")

	// Sign the data
	signature, err := privKey.Sign(testData)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	// Verify the signature
	if rsaPub, ok := pubKey.(RSA4096PublicKey); ok {
		err = rsaPub.Verify(testData, signature)
		if err != nil {
			t.Fatalf("failed to verify signature: %v", err)
		}
	} else {
		t.Fatalf("unexpected public key type: %T", pubKey)
	}
}

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
