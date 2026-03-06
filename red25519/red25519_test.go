package red25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	"github.com/go-i2p/crypto/types"
	upstream "github.com/go-i2p/red25519"
)

// signWithRed25519 is a test helper that generates a Red25519 key pair,
// signs the given message, and returns the public key, signature, and signer.
func signWithRed25519(t *testing.T, message []byte) (*Red25519PublicKey, *Red25519PrivateKey, []byte) {
	t.Helper()
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("Failed to generate key:", err)
	}

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Sign failed:", err)
	}

	return pubKey, privKey, sig
}

// generateRed25519TestSignerVerifier generates a Red25519 key pair and returns
// the signer, verifier, and private key (for deferred Zero).
func generateRed25519TestSignerVerifier(t *testing.T) (types.Signer, types.Verifier, *Red25519PrivateKey) {
	t.Helper()
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("Failed to generate Red25519 key pair:", err)
	}
	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}
	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}
	return signer, verifier, privKey
}

// TestRed25519SignVerifyRoundTrips tests both Sign/Verify and SignHash/VerifyHash round-trips.
func TestRed25519SignVerifyRoundTrips(t *testing.T) {
	tests := []struct {
		name    string
		msgSize int
		sign    func(types.Signer, []byte) ([]byte, error)
		verify  func(types.Verifier, []byte, []byte) error
	}{
		{"Sign/Verify", 256, types.Signer.Sign, types.Verifier.Verify},
		{"SignHash/VerifyHash", 512, types.Signer.SignHash, types.Verifier.VerifyHash},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, verifier, privKey := generateRed25519TestSignerVerifier(t)
			defer privKey.Zero()

			message := make([]byte, tt.msgSize)
			io.ReadFull(rand.Reader, message)

			sig, err := tt.sign(signer, message)
			if err != nil {
				t.Fatalf("%s failed: %v", tt.name, err)
			}

			if tt.name == "Sign/Verify" && len(sig) != SignatureSize {
				t.Fatalf("Signature size = %d, want %d", len(sig), SignatureSize)
			}

			err = tt.verify(verifier, message, sig)
			if err != nil {
				t.Fatalf("%s verification failed: %v", tt.name, err)
			}
		})
	}
}

// TestRed25519DeterministicSignatures verifies that Red25519 (using upstream lib)
// produces deterministic signatures for the same key and message.
func TestRed25519DeterministicSignatures(t *testing.T) {
	_, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("Failed to generate key:", err)
	}
	defer privKey.Zero()

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	message := []byte("test message for determinism check")

	sig1, err := signer.Sign(message)
	if err != nil {
		t.Fatal("First sign failed:", err)
	}

	sig2, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Second sign failed:", err)
	}

	// Upstream red25519 uses deterministic nonces (like standard Ed25519)
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("Two signatures of the same message differ — Red25519 should be deterministic")
	}
}

// TestRed25519WrongKeyRejects verifies that a signature by one key is rejected
// by a different key's verifier.
func TestRed25519WrongKeyRejects(t *testing.T) {
	pubKey1, _, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("Failed to generate key pair 1:", err)
	}

	_, privKey2, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("Failed to generate key pair 2:", err)
	}
	defer privKey2.Zero()

	signer, err := privKey2.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	message := []byte("test message for wrong key rejection")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Sign failed:", err)
	}

	// Verify with the WRONG public key — should fail
	verifier, err := pubKey1.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}
	err = verifier.Verify(message, sig)
	if err == nil {
		t.Fatal("Verify with wrong public key should have failed")
	}
}

// TestRed25519TamperedMessageRejects verifies that modifying the message
// causes verification to fail.
func TestRed25519TamperedMessageRejects(t *testing.T) {
	message := []byte("original message")
	pubKey, privKey, sig := signWithRed25519(t, message)
	defer privKey.Zero()

	// Tamper with message
	tampered := []byte("tampered message")

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}
	err = verifier.Verify(tampered, sig)
	if err == nil {
		t.Fatal("Verify with tampered message should have failed")
	}
}

// TestRed25519TamperedSignatureRejects verifies that modifying the signature
// causes verification to fail.
func TestRed25519TamperedSignatureRejects(t *testing.T) {
	message := []byte("test message for tampered signature")
	pubKey, privKey, sig := signWithRed25519(t, message)
	defer privKey.Zero()

	// Tamper with signature
	sig[0] ^= 0xff

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}
	err = verifier.Verify(message, sig)
	if err == nil {
		t.Fatal("Verify with tampered signature should have failed")
	}
}

// TestRed25519KeyPairGeneration tests key pair generation and interface compliance.
func TestRed25519KeyPairGeneration(t *testing.T) {
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}
	defer privKey.Zero()

	// Verify key sizes
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"PublicKey", pubKey.Len(), PublicKeySize},
		{"PrivateKey", privKey.Len(), PrivateKeySize},
	} {
		if tc.got != tc.want {
			t.Fatalf("%s length = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	// Test round-trip via generateRed25519TestSignerVerifier
	signer, verifier, privKey2 := generateRed25519TestSignerVerifier(t)
	defer privKey2.Zero()
	message := []byte("test message for key pair generation")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Sign failed:", err)
	}
	if err := verifier.Verify(message, sig); err != nil {
		t.Fatal("Verify failed:", err)
	}
}

// TestRed25519PublicKeyBytes tests key byte methods.
func TestRed25519PublicKeyBytes(t *testing.T) {
	pubKey, _, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}

	if pubKey.Len() != PublicKeySize {
		t.Fatalf("Len() = %d, want %d", pubKey.Len(), PublicKeySize)
	}
	if len(pubKey.Bytes()) != PublicKeySize {
		t.Fatalf("Bytes() length = %d, want %d", len(pubKey.Bytes()), PublicKeySize)
	}
}

// TestRed25519PrivateKeyBytes tests private key byte methods.
func TestRed25519PrivateKeyBytes(t *testing.T) {
	_, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}
	defer privKey.Zero()

	if privKey.Len() != PrivateKeySize {
		t.Fatalf("Len() = %d, want %d", privKey.Len(), PrivateKeySize)
	}
	if len(privKey.Bytes()) != PrivateKeySize {
		t.Fatalf("Bytes() length = %d, want %d", len(privKey.Bytes()), PrivateKeySize)
	}
}

// TestRed25519PrivateKeyZero tests that Zero() clears the key material.
func TestRed25519PrivateKeyZero(t *testing.T) {
	_, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}

	privKey.Zero()

	for i, b := range *privKey {
		if b != 0 {
			t.Fatalf("Zero() did not clear byte %d: got %d", i, b)
		}
	}
}

// TestRed25519PublicKeyFromPrivateKey tests public key extraction.
func TestRed25519PublicKeyFromPrivateKey(t *testing.T) {
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}
	defer privKey.Zero()

	// Extract public key from private key
	derivedPub, err := privKey.Public()
	if err != nil {
		t.Fatal("Public() failed:", err)
	}

	if !bytes.Equal(pubKey.Bytes(), derivedPub.Bytes()) {
		t.Fatal("Public key derived from private key doesn't match generated public key")
	}
}

// TestRed25519GenerateKey tests the GenerateRed25519Key convenience function.
func TestRed25519GenerateKey(t *testing.T) {
	privKey, err := GenerateRed25519Key()
	if err != nil {
		t.Fatal("GenerateRed25519Key failed:", err)
	}

	if privKey.Len() != PrivateKeySize {
		t.Fatalf("Private key length = %d, want %d", privKey.Len(), PrivateKeySize)
	}
}

// TestRed25519PrivateKeyGenerate tests the Generate() method.
func TestRed25519PrivateKeyGenerate(t *testing.T) {
	_, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}
	defer privKey.Zero()

	newKey, err := privKey.Generate()
	if err != nil {
		t.Fatal("Generate() failed:", err)
	}

	if newKey.Len() != PrivateKeySize {
		t.Fatalf("Generated key length = %d, want %d", newKey.Len(), PrivateKeySize)
	}

	// New key should be different from original
	newKeyTyped := newKey.(Red25519PrivateKey)
	if bytes.Equal(privKey.Bytes(), newKeyTyped.Bytes()) {
		t.Fatal("Generated key should be different from original")
	}
}

// TestNewRed25519KeyConstructors tests constructor validation for both public and private keys.
func TestNewRed25519KeyConstructors(t *testing.T) {
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}
	defer privKey.Zero()

	tests := []struct {
		name        string
		constructor func([]byte) (interface{ Bytes() []byte }, error)
		invalidData []byte
		validData   []byte
	}{
		{
			name: "PublicKey",
			constructor: func(data []byte) (interface{ Bytes() []byte }, error) {
				return NewRed25519PublicKey(data)
			},
			invalidData: []byte{1, 2, 3},
			validData:   pubKey.Bytes(),
		},
		{
			name: "PrivateKey",
			constructor: func(data []byte) (interface{ Bytes() []byte }, error) {
				return NewRed25519PrivateKey(data)
			},
			invalidData: []byte{1, 2, 3},
			validData:   privKey.Bytes(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_invalid_size", func(t *testing.T) {
			_, err := tt.constructor(tt.invalidData)
			if err == nil {
				t.Fatalf("New%s should reject invalid size", tt.name)
			}
		})

		t.Run(tt.name+"_valid_roundtrip", func(t *testing.T) {
			restored, err := tt.constructor(tt.validData)
			if err != nil {
				t.Fatalf("New%s with valid data failed: %v", tt.name, err)
			}

			if !bytes.Equal(tt.validData, restored.Bytes()) {
				t.Fatalf("Restored %s doesn't match original", tt.name)
			}
		})
	}
}

// TestRed25519InvalidKeySizes tests error handling for invalid key sizes.
func TestRed25519InvalidKeySizes(t *testing.T) {
	// Signer with bad key - create directly with upstream PrivateKey
	badSigner := &Red25519Signer{k: upstream.PrivateKey([]byte{1, 2, 3})}
	_, err := badSigner.Sign([]byte("test"))
	if err == nil {
		t.Fatal("Sign with bad key should fail")
	}

	// Verifier with bad key
	badVerifier := &Red25519Verifier{k: upstream.PublicKey([]byte{1, 2, 3})}
	err = badVerifier.Verify([]byte("test"), make([]byte, SignatureSize))
	if err == nil {
		t.Fatal("Verify with bad key should fail")
	}
}

// TestRed25519VerifierFromPrivateKey tests creating a verifier from a private key.
func TestRed25519VerifierFromPrivateKey(t *testing.T) {
	_, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}
	defer privKey.Zero()

	verifier, err := privKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier from private key failed:", err)
	}

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	message := []byte("test message for verifier from private key")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Sign failed:", err)
	}

	if err := verifier.Verify(message, sig); err != nil {
		t.Fatal("Verify via private key verifier failed:", err)
	}
}

// TestRed25519EmptyMessage tests signing and verifying an empty message.
func TestRed25519EmptyMessage(t *testing.T) {
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}
	defer privKey.Zero()

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	sig, err := signer.Sign([]byte{})
	if err != nil {
		t.Fatal("Sign empty message failed:", err)
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}

	if err := verifier.Verify([]byte{}, sig); err != nil {
		t.Fatal("Verify empty message failed:", err)
	}
}

// TestRed25519LargeMessage tests signing and verifying a large message.
func TestRed25519LargeMessage(t *testing.T) {
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}
	defer privKey.Zero()

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	// 1 MB message
	message := make([]byte, 1<<20)
	io.ReadFull(rand.Reader, message)

	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Sign large message failed:", err)
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}

	if err := verifier.Verify(message, sig); err != nil {
		t.Fatal("Verify large message failed:", err)
	}
}

// TestRed25519Ed25519Interop verifies that unblinded Red25519 signatures
// are byte-identical to standard Ed25519 signatures (as guaranteed by upstream).
func TestRed25519Ed25519Interop(t *testing.T) {
	// Generate with upstream, get the raw ed25519 key pair
	pub, priv, err := upstream.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("GenerateKey failed:", err)
	}

	message := []byte("interop test message")

	// Sign with Red25519
	redSig := upstream.Sign(priv, message)

	// Verify with standard crypto/ed25519
	stdPub := ed25519.PublicKey(pub)
	if !ed25519.Verify(stdPub, message, redSig) {
		t.Fatal("Standard ed25519.Verify rejected Red25519 signature — interop broken")
	}

	// Sign with standard Ed25519
	stdPriv := ed25519.PrivateKey(priv)
	stdSig := ed25519.Sign(stdPriv, message)

	// Verify with Red25519
	if !upstream.Verify(pub, message, stdSig) {
		t.Fatal("Red25519.Verify rejected standard Ed25519 signature — interop broken")
	}
}

// TestRed25519BlindedSignature tests key blinding and blinded signature verification.
func TestRed25519BlindedSignature(t *testing.T) {
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}
	defer privKey.Zero()

	// Generate blinding factor
	bf, err := GenerateBlindingFactor(nil)
	if err != nil {
		t.Fatal("GenerateBlindingFactor failed:", err)
	}

	// Blind both keys
	blindedPub, err := BlindPublicKey(*pubKey, bf)
	if err != nil {
		t.Fatal("BlindPublicKey failed:", err)
	}

	blindedPriv, err := BlindPrivateKey(*privKey, bf)
	if err != nil {
		t.Fatal("BlindPrivateKey failed:", err)
	}

	// Sign with blinded private key
	blindedSigner := &Red25519Signer{k: upstream.PrivateKey(blindedPriv)}
	message := []byte("blinded message test")
	sig, err := blindedSigner.Sign(message)
	if err != nil {
		t.Fatal("Sign with blinded key failed:", err)
	}

	// Verify with blinded public key
	blindedVerifier := &Red25519Verifier{k: upstream.PublicKey(blindedPub)}
	if err := blindedVerifier.Verify(message, sig); err != nil {
		t.Fatal("Verify with blinded key failed:", err)
	}

	// Original public key should NOT verify the blinded signature
	origVerifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}
	if err := origVerifier.Verify(message, sig); err == nil {
		t.Fatal("Original public key should not verify blinded signature")
	}
}

// TestRed25519NewKeyFromSeed tests deterministic key derivation from seed.
func TestRed25519NewKeyFromSeed(t *testing.T) {
	seed := make([]byte, SeedSize)
	io.ReadFull(rand.Reader, seed)

	priv1 := NewKeyFromSeed(seed)
	priv2 := NewKeyFromSeed(seed)

	if !bytes.Equal(priv1.Bytes(), priv2.Bytes()) {
		t.Fatal("Same seed should produce same private key")
	}
}

// BenchmarkRed25519Sign benchmarks Red25519 signing.
func BenchmarkRed25519Sign(b *testing.B) {
	_, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		b.Fatal(err)
	}

	signer, err := privKey.NewSigner()
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark message for red25519 signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRed25519Verify benchmarks Red25519 verification.
func BenchmarkRed25519Verify(b *testing.B) {
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		b.Fatal(err)
	}

	signer, err := privKey.NewSigner()
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark message for red25519 verification")
	sig, err := signer.Sign(message)
	if err != nil {
		b.Fatal(err)
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := verifier.Verify(message, sig)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRed25519KeyGen benchmarks Red25519 key pair generation.
func BenchmarkRed25519KeyGen(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateRed25519KeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}
