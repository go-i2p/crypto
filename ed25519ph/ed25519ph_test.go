package ed25519ph

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"io"
	"testing"
)

func TestEd25519ph(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Failed to generate ed25519 test key:", err)
	}

	pubKey := Ed25519phPublicKey(pub)
	signer := &Ed25519phSigner{k: priv}

	message := make([]byte, 256)
	io.ReadFull(rand.Reader, message)

	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Failed to sign message:", err)
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

// TestEd25519phSignHashRoundTrip tests signing and verifying a pre-computed hash.
func TestEd25519phSignHashRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Failed to generate key:", err)
	}

	pubKey := Ed25519phPublicKey(pub)
	signer := &Ed25519phSigner{k: priv}

	message := make([]byte, 512)
	io.ReadFull(rand.Reader, message)

	h := sha512.Sum512(message)
	sig, err := signer.SignHash(h[:])
	if err != nil {
		t.Fatal("SignHash failed:", err)
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}

	err = verifier.VerifyHash(h[:], sig)
	if err != nil {
		t.Fatal("VerifyHash failed:", err)
	}
}

// TestEd25519phStdlibInterop verifies that our Ed25519ph signatures are
// compatible with Go's stdlib ed25519.VerifyWithOptions using Hash: crypto.SHA512.
func TestEd25519phStdlibInterop(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Failed to generate key:", err)
	}

	message := make([]byte, 256)
	io.ReadFull(rand.Reader, message)
	h := sha512.Sum512(message)

	// Sign with our wrapper
	signer := &Ed25519phSigner{k: priv}
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Sign failed:", err)
	}

	// Verify with stdlib VerifyWithOptions — proves RFC 8032 Ed25519ph interop
	opts := &ed25519.Options{Hash: crypto.SHA512}
	err = ed25519.VerifyWithOptions(pub, h[:], sig, opts)
	if err != nil {
		t.Fatal("Stdlib VerifyWithOptions rejected our Ed25519ph signature — not RFC 8032 compliant:", err)
	}

	// Sign with stdlib
	stdlibSig, err := priv.Sign(nil, h[:], opts)
	if err != nil {
		t.Fatal("Stdlib Sign failed:", err)
	}

	// Verify with our wrapper — proves we accept stdlib Ed25519ph signatures
	pubKey := Ed25519phPublicKey(pub)
	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}
	if err := verifier.Verify(message, stdlibSig); err != nil {
		t.Fatal("Ed25519phVerifier rejects stdlib Ed25519ph signature — not RFC 8032 compliant:", err)
	}
}

// TestEd25519phNotInteropWithPureEdDSA confirms that Ed25519ph signatures
// are NOT compatible with PureEdDSA (standard Ed25519). This is expected
// behavior per RFC 8032 — the two modes use different domain separation.
func TestEd25519phNotInteropWithPureEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Failed to generate key:", err)
	}

	message := make([]byte, 128)
	io.ReadFull(rand.Reader, message)

	// Sign with Ed25519ph
	signer := &Ed25519phSigner{k: priv}
	phSig, err := signer.Sign(message)
	if err != nil {
		t.Fatal("Ed25519ph Sign failed:", err)
	}

	// Attempt to verify Ed25519ph signature with PureEdDSA — should fail
	if ed25519.Verify(pub, message, phSig) {
		t.Fatal("Ed25519ph signature was accepted by PureEdDSA Verify — this should not happen")
	}

	// Sign with PureEdDSA
	pureSig := ed25519.Sign(priv, message)

	// Attempt to verify PureEdDSA signature with Ed25519ph — should fail
	pubKey := Ed25519phPublicKey(pub)
	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Fatal("NewVerifier failed:", err)
	}
	if err := verifier.Verify(message, pureSig); err == nil {
		t.Fatal("PureEdDSA signature was accepted by Ed25519ph Verify — this should not happen")
	}
}

// TestEd25519phKeyPairGeneration tests key pair generation and round-trip.
func TestEd25519phKeyPairGeneration(t *testing.T) {
	pubKey, privKey, err := GenerateEd25519phKeyPair()
	if err != nil {
		t.Fatal("GenerateEd25519phKeyPair failed:", err)
	}
	defer privKey.Zero()

	if pubKey.Len() != ed25519.PublicKeySize {
		t.Fatalf("Public key length = %d, want %d", pubKey.Len(), ed25519.PublicKeySize)
	}
	if privKey.Len() != ed25519.PrivateKeySize {
		t.Fatalf("Private key length = %d, want %d", privKey.Len(), ed25519.PrivateKeySize)
	}

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatal("NewSigner failed:", err)
	}

	message := []byte("test message for ed25519ph key pair")
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

// TestEd25519phPublicKeyBytes tests key byte methods.
func TestEd25519phPublicKeyBytes(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	key, err := NewEd25519phPublicKey(pub)
	if err != nil {
		t.Fatal("NewEd25519phPublicKey failed:", err)
	}

	if key.Len() != ed25519.PublicKeySize {
		t.Fatalf("Len() = %d, want %d", key.Len(), ed25519.PublicKeySize)
	}
	if len(key.Bytes()) != ed25519.PublicKeySize {
		t.Fatalf("Bytes() length = %d, want %d", len(key.Bytes()), ed25519.PublicKeySize)
	}
}

// TestEd25519phPrivateKeyZero tests that Zero() clears the key material.
func TestEd25519phPrivateKeyZero(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	key, err := NewEd25519phPrivateKey(priv)
	if err != nil {
		t.Fatal("NewEd25519phPrivateKey failed:", err)
	}

	key.Zero()

	for i, b := range key {
		if b != 0 {
			t.Fatalf("Zero() did not clear byte %d: got %d", i, b)
		}
	}
}

// TestEd25519phInvalidKeySizes tests error handling for invalid key sizes.
func TestEd25519phInvalidKeySizes(t *testing.T) {
	// Invalid public key
	_, err := NewEd25519phPublicKey([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("NewEd25519phPublicKey should reject invalid size")
	}

	// Invalid private key
	_, err = NewEd25519phPrivateKey([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("NewEd25519phPrivateKey should reject invalid size")
	}

	// Signer with bad key
	badSigner := &Ed25519phSigner{k: []byte{1, 2, 3}}
	_, err = badSigner.Sign([]byte("test"))
	if err == nil {
		t.Fatal("Sign with bad key should fail")
	}

	// Verifier with bad key
	badVerifier := &Ed25519phVerifier{k: []byte{1, 2, 3}}
	err = badVerifier.Verify([]byte("test"), make([]byte, ed25519.SignatureSize))
	if err == nil {
		t.Fatal("Verify with bad key should fail")
	}
}
