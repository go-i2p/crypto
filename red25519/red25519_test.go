package red25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	upstream "github.com/go-i2p/red25519"
)

// TestRed25519SignVerify tests basic sign and verify round-trip.
func TestRed25519SignVerify(t *testing.T) {
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("Failed to generate Red25519 key pair:", err)
	}
	defer privKey.Zero()

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner error:", err)
	}

	message := make([]byte, 256)
	io.ReadFull(rand.Reader, message)

	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Failed to sign message:", err)
	}

	if len(sig) != SignatureSize {
		t.Fatalf("Signature size = %d, want %d", len(sig), SignatureSize)
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier error:", err)
	}

	err = verifier.Verify(message, sig)
	if err != nil {
		t.Fatal("Failed to verify message:", err)
	}
}

// TestRed25519SignHashRoundTrip tests signing and verifying via SignHash.
func TestRed25519SignHashRoundTrip(t *testing.T) {
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("Failed to generate key:", err)
	}
	defer privKey.Zero()

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	message := make([]byte, 512)
	io.ReadFull(rand.Reader, message)

	sig, err := signer.SignHash(message)
	if err != nil {
		t.Fatal("SignHash failed:", err)
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}

	err = verifier.VerifyHash(message, sig)
	if err != nil {
		t.Fatal("VerifyHash failed:", err)
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
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("Failed to generate key:", err)
	}
	defer privKey.Zero()

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	message := []byte("original message")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Sign failed:", err)
	}

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
	pubKey, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("Failed to generate key:", err)
	}
	defer privKey.Zero()

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	message := []byte("test message for tampered signature")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Sign failed:", err)
	}

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

	if pubKey.Len() != PublicKeySize {
		t.Fatalf("Public key length = %d, want %d", pubKey.Len(), PublicKeySize)
	}
	if privKey.Len() != PrivateKeySize {
		t.Fatalf("Private key length = %d, want %d", privKey.Len(), PrivateKeySize)
	}

	// Test round-trip via interface methods
	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	message := []byte("test message for key pair generation")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Sign failed:", err)
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
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

// TestNewRed25519PublicKey tests constructor validation.
func TestNewRed25519PublicKey(t *testing.T) {
	// Invalid size
	_, err := NewRed25519PublicKey([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("NewRed25519PublicKey should reject invalid size")
	}

	// Valid - generate a real public key
	pubKey, _, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}

	restored, err := NewRed25519PublicKey(pubKey.Bytes())
	if err != nil {
		t.Fatal("NewRed25519PublicKey with valid data failed:", err)
	}

	if !bytes.Equal(pubKey.Bytes(), restored.Bytes()) {
		t.Fatal("Restored public key doesn't match original")
	}
}

// TestNewRed25519PrivateKey tests constructor validation.
func TestNewRed25519PrivateKey(t *testing.T) {
	// Invalid size
	_, err := NewRed25519PrivateKey([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("NewRed25519PrivateKey should reject invalid size")
	}

	// Valid - generate a real private key
	_, privKey, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatal("GenerateRed25519KeyPair failed:", err)
	}

	restored, err := NewRed25519PrivateKey(privKey.Bytes())
	if err != nil {
		t.Fatal("NewRed25519PrivateKey with valid data failed:", err)
	}
	defer restored.Zero()

	if !bytes.Equal(privKey.Bytes(), restored.Bytes()) {
		t.Fatal("Restored private key doesn't match original")
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
