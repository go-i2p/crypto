package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
)

// generateValidAlpha creates a valid Ed25519 scalar for use as a blinding factor
func generateValidAlpha() ([32]byte, error) {
	var alpha [32]byte

	// Generate 64 random bytes for SetUniformBytes
	alphaBytes := make([]byte, 64)
	_, err := rand.Read(alphaBytes)
	if err != nil {
		return alpha, err
	}

	// Create a valid scalar using SetUniformBytes (requires 64 bytes)
	alphaScalar, err := (&edwards25519.Scalar{}).SetUniformBytes(alphaBytes)
	if err != nil {
		return alpha, err
	}

	copy(alpha[:], alphaScalar.Bytes())
	return alpha, nil
}

// generateTestPubKeyAndAlpha generates a test Ed25519 public key (as [32]byte)
// and a valid blinding factor alpha for use in blinding tests.
func generateTestPubKeyAndAlpha(t *testing.T) ([32]byte, [32]byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	var pubKey [32]byte
	copy(pubKey[:], pub)
	alpha, err := generateValidAlpha()
	if err != nil {
		t.Fatalf("Failed to generate alpha: %v", err)
	}
	return pubKey, alpha
}

// generateTestPrivKeyAndAlpha generates a test Ed25519 private key (as [64]byte)
// and a valid blinding factor alpha for use in blinding tests.
func generateTestPrivKeyAndAlpha(t *testing.T) ([64]byte, [32]byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	var privKey [64]byte
	copy(privKey[:], priv)
	alpha, err := generateValidAlpha()
	if err != nil {
		t.Fatalf("Failed to generate alpha: %v", err)
	}
	return privKey, alpha
}

// generateTestKeypairAndAlpha generates a test Ed25519 keypair and a valid
// blinding factor alpha for use in blinding tests.
func generateTestKeypairAndAlpha(t *testing.T) ([32]byte, [64]byte, [32]byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	var pubKey [32]byte
	var privKey [64]byte
	copy(pubKey[:], pub)
	copy(privKey[:], priv)
	alpha, err := generateValidAlpha()
	if err != nil {
		t.Fatalf("Failed to generate alpha: %v", err)
	}
	return pubKey, privKey, alpha
}

// assertBlindDeterministic is a test helper that verifies a blinding function
// produces identical results when called multiple times with the same inputs.
func assertBlindDeterministic(t *testing.T, blindFunc func() ([]byte, error)) {
	t.Helper()

	blinded1, err := blindFunc()
	if err != nil {
		t.Fatalf("First blinding failed: %v", err)
	}

	blinded2, err := blindFunc()
	if err != nil {
		t.Fatalf("Second blinding failed: %v", err)
	}

	blinded3, err := blindFunc()
	if err != nil {
		t.Fatalf("Third blinding failed: %v", err)
	}

	if !bytes.Equal(blinded1, blinded2) {
		t.Error("First and second blinding produced different results")
	}

	if !bytes.Equal(blinded1, blinded3) {
		t.Error("First and third blinding produced different results")
	}
}

func TestBlindPublicKey(t *testing.T) {
	pubKey, alpha := generateTestPubKeyAndAlpha(t)

	// Blind the public key
	blindedPub, err := BlindPublicKey(pubKey, alpha)
	if err != nil {
		t.Fatalf("BlindPublicKey failed: %v", err)
	}

	// Verify result is 32 bytes
	if len(blindedPub) != 32 {
		t.Errorf("Expected 32-byte result, got %d", len(blindedPub))
	}

	// Verify result is different from original
	if bytes.Equal(blindedPub[:], pubKey[:]) {
		t.Error("Blinded public key equals original (should be different)")
	}

	// Verify result is not all zeros
	allZero := true
	for _, b := range blindedPub {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Blinded public key is all zeros")
	}
}

func TestBlindPublicKeyDeterminism(t *testing.T) {
	pubKey, alpha := generateTestPubKeyAndAlpha(t)

	assertBlindDeterministic(t, func() ([]byte, error) {
		b, err := BlindPublicKey(pubKey, alpha)
		return b[:], err
	})
}

func TestBlindPublicKeyInvalidInputs(t *testing.T) {
	// Generate a valid alpha for the tests
	alpha, err := generateValidAlpha()
	if err != nil {
		t.Fatalf("Failed to generate alpha: %v", err)
	}

	tests := []struct {
		name      string
		publicKey [32]byte
		wantErr   bool
	}{
		{
			name: "invalid public key - non-canonical encoding",
			publicKey: func() [32]byte {
				var bad [32]byte
				// Create an invalid point encoding
				// Set the high bit and use values that don't encode a valid point
				bad[31] = 0x80 // High bit set
				for i := 0; i < 31; i++ {
					bad[i] = 0xFF
				}
				return bad
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BlindPublicKey(tt.publicKey, alpha)
			if tt.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestBlindUnblindRoundTrip(t *testing.T) {
	original, alpha := generateTestPubKeyAndAlpha(t)

	// Blind the key
	blinded, err := BlindPublicKey(original, alpha)
	if err != nil {
		t.Fatalf("BlindPublicKey failed: %v", err)
	}

	// Unblind it
	recovered, err := UnblindPublicKey(blinded, alpha)
	if err != nil {
		t.Fatalf("UnblindPublicKey failed: %v", err)
	}

	// Verify we got back the original
	if !bytes.Equal(recovered[:], original[:]) {
		t.Error("Unblinded key does not match original")
		t.Logf("Original:  %x", original)
		t.Logf("Recovered: %x", recovered)
	}
}

func TestBlindPrivateKey(t *testing.T) {
	privKey, alpha := generateTestPrivKeyAndAlpha(t)

	// Blind the private key
	blindedPriv, err := BlindPrivateKey(privKey, alpha)
	if err != nil {
		t.Fatalf("BlindPrivateKey failed: %v", err)
	}

	// Verify result is 64 bytes
	if len(blindedPriv) != 64 {
		t.Errorf("Expected 64-byte result, got %d", len(blindedPriv))
	}

	// Verify result is different from original
	if bytes.Equal(blindedPriv[:], privKey[:]) {
		t.Error("Blinded private key equals original (should be different)")
	}
}

func TestBlindPrivateKeyDeterminism(t *testing.T) {
	privKey, alpha := generateTestPrivKeyAndAlpha(t)

	assertBlindDeterministic(t, func() ([]byte, error) {
		b, err := BlindPrivateKey(privKey, alpha)
		return b[:], err
	})
}

func TestBlindKeysConsistency(t *testing.T) {
	pubKey, privKey, alpha := generateTestKeypairAndAlpha(t)

	// Blind both keys
	blindedPub, err := BlindPublicKey(pubKey, alpha)
	if err != nil {
		t.Fatalf("BlindPublicKey failed: %v", err)
	}

	blindedPriv, err := BlindPrivateKey(privKey, alpha)
	if err != nil {
		t.Fatalf("BlindPrivateKey failed: %v", err)
	}

	// Extract public key from blinded private key (last 32 bytes)
	blindedPubFromPriv := blindedPriv[32:]

	// Verify they match
	if !bytes.Equal(blindedPub[:], blindedPubFromPriv[:]) {
		t.Error("Blinded public key does not match public key derived from blinded private key")
		t.Logf("BlindPublicKey:  %x", blindedPub)
		t.Logf("From private:    %x", blindedPubFromPriv)
	}
}

func TestBlindedSignatureVerification(t *testing.T) {
	t.Skip("Blinded private keys cannot be used directly with crypto/ed25519.Sign - see BlindPrivateKey documentation")

	// This test is skipped because Go's crypto/ed25519.Sign expects the private key
	// to be in [seed][pubkey] format, but BlindPrivateKey returns [scalar][pubkey] format.
	// To use blinded keys for signing, the scalar must be extracted and used with
	// the edwards25519 library directly.
}

func TestBlindPublicKeyWithZeroAlpha(t *testing.T) {
	// Generate a test keypair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	var pubKey [32]byte
	copy(pubKey[:], pub)

	// Use zero alpha
	var zeroAlpha [32]byte

	// Blind with zero alpha (should be equivalent to adding identity)
	blinded, err := BlindPublicKey(pubKey, zeroAlpha)
	if err != nil {
		t.Fatalf("BlindPublicKey with zero alpha failed: %v", err)
	}

	// Result should equal original (P + [0]B = P)
	if !bytes.Equal(blinded[:], pubKey[:]) {
		t.Error("Blinding with zero alpha should return original key")
	}
}

func TestBlindPublicKeyDifferentAlphas(t *testing.T) {
	pubKey, alpha1 := generateTestPubKeyAndAlpha(t)

	alpha2, err := generateValidAlpha()
	if err != nil {
		t.Fatalf("Failed to generate alpha2: %v", err)
	}

	// Blind with different alphas
	blinded1, err := BlindPublicKey(pubKey, alpha1)
	if err != nil {
		t.Fatalf("First blinding failed: %v", err)
	}

	blinded2, err := BlindPublicKey(pubKey, alpha2)
	if err != nil {
		t.Fatalf("Second blinding failed: %v", err)
	}

	// Results should be different
	if bytes.Equal(blinded1[:], blinded2[:]) {
		t.Error("Different alphas produced same blinded key")
	}
}

// TestUnblindPublicKey and TestBlindingWithEdwards25519Scalars removed:
// covered by TestBlindUnblindRoundTrip and TestBlindPublicKey respectively.

// BenchmarkBlindPublicKey benchmarks public key blinding
func BenchmarkBlindPublicKey(b *testing.B) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var pubKey [32]byte
	copy(pubKey[:], pub)

	alpha, err := generateValidAlpha()
	if err != nil {
		b.Fatalf("Failed to generate alpha: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := BlindPublicKey(pubKey, alpha)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBlindPrivateKey benchmarks private key blinding
func BenchmarkBlindPrivateKey(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var privKey [64]byte
	copy(privKey[:], priv)

	alpha, err := generateValidAlpha()
	if err != nil {
		b.Fatalf("Failed to generate alpha: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := BlindPrivateKey(privKey, alpha)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnblindPublicKey benchmarks public key unblinding
func BenchmarkUnblindPublicKey(b *testing.B) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var pubKey [32]byte
	copy(pubKey[:], pub)

	alpha, err := generateValidAlpha()
	if err != nil {
		b.Fatalf("Failed to generate alpha: %v", err)
	}

	blinded, _ := BlindPublicKey(pubKey, alpha)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnblindPublicKey(blinded, alpha)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBlindedSignature benchmarks signing with a blinded key
// Note: This benchmark is disabled because blinded keys cannot be used with crypto/ed25519.Sign
func BenchmarkBlindedSignature(b *testing.B) {
	b.Skip("Blinded private keys cannot be used directly with crypto/ed25519.Sign")
}
