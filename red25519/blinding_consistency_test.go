package red25519_test

// F-10: the two packages that blind keys must implement the SAME scheme.
//
// encryptedleaseset.md §Blinding Calculations defines exactly one pair of
// operations:
//
//	blinded signing private key = a' = BLIND_PRIVKEY(a, alpha) = (a + alpha) mod L
//	blinded public key = A' = BLIND_PUBKEY(A, alpha) = A + DERIVE_PUBLIC(alpha)
//
// and states the invariant that must hold: "Both methods of calculating A' yield
// the same result, as required."
//
// Before this fix, ed25519 used the additive scheme and red25519 a multiplicative
// one under identical function names and signatures, so a caller could blind the
// private key with one package and the public key with the other, get a keypair
// whose signatures never verify, and see no type error and no runtime signal.
// These tests pin the agreement.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	cryptoed25519 "github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/red25519"
)

// TestBlindingAgreesWithEd25519Blinding drives the same alpha through both
// packages and requires the same blinded public key.
func TestBlindingAgreesWithEd25519Blinding(t *testing.T) {
	// An Ed25519 destination key, converted to Red25519 the way the spec allows.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub := edPriv.Public().(ed25519.PublicKey)

	// A real blinding factor from the spec's GENERATE_ALPHA.
	alpha, err := kdf.DeriveBlindingFactorI2P(edPub[:], "", kdf.SigTypeRedDSASha512Ed25519, time.Now())
	if err != nil {
		t.Fatalf("DeriveBlindingFactorI2P: %v", err)
	}

	// Blind the Ed25519 public key with the ed25519 package.
	var edPubArr [32]byte
	copy(edPubArr[:], edPub)
	edBlinded, err := cryptoed25519.BlindPublicKey(edPubArr, alpha)
	if err != nil {
		t.Fatalf("ed25519.BlindPublicKey: %v", err)
	}

	// Blind the same key via the Red25519 path.
	rvk, err := red25519.ConvertEd25519PublicKey(edPub)
	if err != nil {
		t.Fatalf("ConvertEd25519PublicKey: %v", err)
	}
	var bf red25519.BlindingFactor
	copy(bf[:], alpha[:])
	redBlinded, err := red25519.BlindPublicKey(rvk, bf)
	if err != nil {
		t.Fatalf("red25519.BlindPublicKey: %v", err)
	}

	if !bytes.Equal(edBlinded[:], redBlinded.Bytes()) {
		t.Errorf("the two packages disagree on the blinded public key for the same alpha:\n  ed25519  = %x\n  red25519 = %x",
			edBlinded, redBlinded.Bytes())
	}
}

// TestBlindedKeyPairCrossVerifies checks the practical hazard: a private key
// blinded by one package must sign validly for a public key blinded by the other.
// If the schemes differ this fails silently at signature-verification time in
// production, which is exactly what F-10 describes.
func TestBlindedKeyPairCrossVerifies(t *testing.T) {
	sk, err := red25519.GenerateRed25519Key()
	if err != nil {
		t.Fatal(err)
	}
	priv := sk.(red25519.Red25519PrivateKey)
	pubAny, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	pub := pubAny.(red25519.Red25519PublicKey)

	alpha, err := red25519.GenerateBlindingFactor(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rpriv, err := red25519.BlindPrivateKey(priv, alpha)
	if err != nil {
		t.Fatal(err)
	}
	rpub, err := red25519.BlindPublicKey(pub, alpha)
	if err != nil {
		t.Fatal(err)
	}

	// The blinded private key's own public key must equal the blinded public key.
	derived, err := rpriv.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived.Bytes(), rpub.Bytes()) {
		t.Fatalf("DERIVE_PUBLIC(RANDOMIZE_PRIVATE(sk,a)) != RANDOMIZE_PUBLIC(vk,a):\n  %x\n  %x",
			derived.Bytes(), rpub.Bytes())
	}

	// And signatures must verify.
	msg := []byte("encrypted lease set authentication")
	signer, err := rpriv.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	v, err := rpub.NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(msg, sig); err != nil {
		t.Errorf("blinded signature failed to verify: %v", err)
	}
}

// TestRed25519PrivateKeyIs32Bytes pins the length divergence F-7/F-8 reported:
// common-structures.md §SigningPrivateKey says RedDSA_SHA512_Ed25519 is 32 bytes,
// so a Java-generated blinded key must be loadable.
func TestRed25519PrivateKeyIs32Bytes(t *testing.T) {
	if red25519.PrivateKeySize != 32 {
		t.Fatalf("PrivateKeySize = %d, want 32", red25519.PrivateKeySize)
	}
	// Take the spec's own vector-1 sk and load it.
	sk, err := hex.DecodeString("58e86efb75fa4e2c410f46e16de9f6acae1a1703528651b69bc176c088bef36e")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := red25519.NewRed25519PrivateKey(sk)
	if err != nil {
		t.Fatalf("NewRed25519PrivateKey rejected the spec's own sk: %v", err)
	}
	if len(priv) != 32 {
		t.Errorf("loaded key is %d bytes", len(priv))
	}
}
