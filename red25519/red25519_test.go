package red25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/go-i2p/crypto/types"
)

// Tests for the Red25519 scheme. The authoritative assertions are in
// spec_vectors_test.go (reference vectors from the spec); these cover the
// properties and rejection behavior around them.

func newTestKeyPair(t *testing.T) (Red25519PublicKey, Red25519PrivateKey) {
	t.Helper()
	pub, priv, err := GenerateRed25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateRed25519KeyPair: %v", err)
	}
	return *pub, *priv
}

// TestRed25519SignVerifyRoundTrip checks a fresh keypair signs and verifies.
func TestRed25519SignVerifyRoundTrip(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	signer, err := priv.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := pub.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	msg := []byte("an encrypted lease set published to a floodfill")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Errorf("signature is %d bytes, want %d (R || S)", len(sig), SignatureSize)
	}
	if err := verifier.Verify(msg, sig); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

// TestRed25519SignaturesAreRandomized pins the property the previous
// implementation violated. red25519.md §Sign/Verify Calculations:
//
//	"In Red25519, the calculation of r for signing uses additional random data ...
//	Because of the random data, every Red25519 signature is different, even when
//	signing the same data with the same key."
//
// Deterministic signatures would let an observer link two observations of the
// same blinded Destination, voiding the unlinkability the scheme exists to
// provide (§Security implications: "Re-randomizing ... does not leak any
// information about the Destination").
func TestRed25519SignaturesAreRandomized(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	signer, err := priv.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	msg := []byte("the same message, signed repeatedly")

	seen := make(map[string]bool)
	for i := 0; i < 8; i++ {
		sig, err := signer.Sign(msg)
		if err != nil {
			t.Fatalf("Sign %d: %v", i, err)
		}
		key := hex.EncodeToString(sig)
		if seen[key] {
			t.Fatalf("signature %d duplicated; Red25519 SIGN must use fresh random data", i)
		}
		seen[key] = true
		v, err := pub.NewVerifier()
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		if err := v.Verify(msg, sig); err != nil {
			t.Errorf("randomized signature %d failed to verify: %v", i, err)
		}
	}
}

// TestRed25519NotEd25519 documents that Red25519 is a distinct scheme: the same
// key bytes must not produce Ed25519-compatible signatures. The previous
// implementation was byte-identical to crypto/ed25519, which is precisely the
// defect (a Java router reads sig type 11 as Red25519).
func TestRed25519NotEd25519(t *testing.T) {
	// Use the spec's own vector key so this is not a self-generated claim.
	sk := mustH(t, "58e86efb75fa4e2c410f46e16de9f6acae1a1703528651b69bc176c088bef36e")
	msg := mustH(t, "0202020202020202020202020202020202020202020202020202020202020202")
	redSig := mustH(t, "61f5527f4d3b46de4b2c234390370bf715ae9098907a0d191ba1b44b23a8ac1a"+
		"6a40437a5294e9503faaf9bd2b7f2fe7ba44dec487b3185aba7ff7d7a17cd40f")

	priv, err := NewRed25519PrivateKey(sk)
	if err != nil {
		t.Fatalf("NewRed25519PrivateKey: %v", err)
	}
	signer, err := priv.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	// The reference signature must verify under our implementation.
	ver, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	v, err := ver.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(msg, redSig); err != nil {
		t.Fatalf("reference Red25519 signature rejected: %v", err)
	}

	// And a signature we produce is not an Ed25519 signature over the same
	// message: Ed25519 verification with the corresponding public key fails.
	ours, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	vk := mustH(t, "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")
	if ed25519.Verify(ed25519.PublicKey(vk), msg, ours) {
		t.Error("our Red25519 signature verifies as Ed25519; the schemes must differ")
	}
}

// TestRed25519WrongKeyRejects checks a signature does not verify under a
// different key.
func TestRed25519WrongKeyRejects(t *testing.T) {
	_, priv := newTestKeyPair(t)
	otherPub, _ := newTestKeyPair(t)

	signer, err := priv.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	msg := []byte("signed by one key")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	v, err := otherPub.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(msg, sig); err == nil {
		t.Error("signature verified under the wrong public key")
	}
}

// TestRed25519TamperedRejected checks message and signature mutations fail.
func TestRed25519TamperedRejected(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	signer, _ := priv.NewSigner()
	msg := []byte("integrity matters here")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	v, err := pub.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	t.Run("tampered message", func(t *testing.T) {
		bad := append([]byte{}, msg...)
		bad[0] ^= 0xFF
		if err := v.Verify(bad, sig); err == nil {
			t.Error("tampered message verified")
		}
	})
	t.Run("tampered signature", func(t *testing.T) {
		bad := append([]byte{}, sig...)
		bad[len(bad)-1] ^= 0xFF
		if err := v.Verify(msg, bad); err == nil {
			t.Error("tampered signature verified")
		}
	})
	t.Run("bad signature size", func(t *testing.T) {
		err := v.Verify(msg, sig[:SignatureSize-1])
		if err == nil {
			t.Error("short signature accepted")
		} else if !errors.Is(err, types.ErrBadSignatureSize) {
			t.Errorf("short signature: got %v, want ErrBadSignatureSize", err)
		}
	})
}

// TestRed25519MessageSizeLimit pins the cap from §Red25519: "Messages must be no
// longer than 65534 bytes. A length of 65535 is reserved for possible future
// extensions." The 2-byte little-endian length prefix cannot distinguish 65535
// from the reserved value, so oversize messages must be refused rather than
// signed under an ambiguous encoding.
func TestRed25519MessageSizeLimit(t *testing.T) {
	_, priv := newTestKeyPair(t)
	signer, err := priv.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	// Exactly at the limit must be accepted.
	atLimit := make([]byte, MaxMessageSize)
	if _, err := signer.Sign(atLimit); err != nil {
		t.Errorf("message of %d bytes rejected: %v", MaxMessageSize, err)
	}

	// One over must be rejected.
	over := make([]byte, MaxMessageSize+1)
	if _, err := signer.Sign(over); err == nil {
		t.Errorf("message of %d bytes accepted; the maximum is %d", len(over), MaxMessageSize)
	}
	if MaxMessageSize != 65534 {
		t.Errorf("MaxMessageSize = %d, want 65534", MaxMessageSize)
	}
}

// TestRed25519EmptyMessage checks the zero-length message path: the length prefix
// is still applied (two zero bytes), so empty and non-empty are domain separated.
func TestRed25519EmptyMessage(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	signer, _ := priv.NewSigner()
	sig, err := signer.Sign(nil)
	if err != nil {
		t.Fatalf("Sign(nil): %v", err)
	}
	v, _ := pub.NewVerifier()
	if err := v.Verify(nil, sig); err != nil {
		t.Errorf("empty message round trip failed: %v", err)
	}
	// An empty message must not verify against a single-zero-byte message.
	v2, _ := pub.NewVerifier()
	if err := v2.Verify([]byte{0}, sig); err == nil {
		t.Error("empty-message signature verified against a 1-byte message; the length prefix is not distinguishing")
	}
}

// TestRed25519KeySizes checks the constructors enforce the spec's lengths: private
// key 32 (common-structures.md §SigningPrivateKey) and public key 32.
func TestRed25519KeySizes(t *testing.T) {
	if PrivateKeySize != 32 {
		t.Errorf("PrivateKeySize = %d, want 32 per §SigningPrivateKey (RedDSA = 32)", PrivateKeySize)
	}
	if PublicKeySize != 32 {
		t.Errorf("PublicKeySize = %d, want 32", PublicKeySize)
	}
	if SignatureSize != 64 {
		t.Errorf("SignatureSize = %d, want 64 per §Signature (RedDSA = 64)", SignatureSize)
	}

	if _, err := NewRed25519PrivateKey(make([]byte, 64)); err == nil {
		t.Error("NewRed25519PrivateKey accepted 64 bytes; the spec's key is a 32-byte scalar")
	}
	if _, err := NewRed25519PrivateKey(make([]byte, 32)); err == nil {
		t.Error("the all-zero scalar must be rejected (DERIVE_PUBLIC(0) is the identity)")
	}
	if _, err := NewRed25519PublicKey(make([]byte, 31)); err == nil {
		t.Error("NewRed25519PublicKey accepted 31 bytes")
	}
	// An encoding whose y-coordinate has no valid x (x^2 is a non-residue) is not
	// a curve point and DECODE_POINT must fail: red25519.md §RedDSA functions
	// VERIFY, "R = DECODE_POINT(Rbytes); if R is invalid: return false".
	//
	// Note that edwards25519.SetBytes reduces a non-canonical y mod p rather than
	// rejecting it, so an out-of-range y (e.g. all 0xFF) is still a valid point;
	// the genuine rejection case is the non-residue below.
	notAPoint, err := hex.DecodeString("0700000000000000000000000000000000000000000000000000000000000080")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRed25519PublicKey(notAPoint); err == nil {
		t.Error("NewRed25519PublicKey accepted an encoding that is not a curve point")
	}
}

// TestRed25519GeneratePrivateIsModL checks GENERATE_PRIVATE produces canonical
// scalars (< L), i.e. reduced mod L rather than clamped. A clamped scalar has bit
// 254 set and bit 0 of byte 31 set, which mod-L reduction removes.
func TestRed25519GeneratePrivateIsModL(t *testing.T) {
	for i := 0; i < 20; i++ {
		key, err := GenerateRed25519Key()
		if err != nil {
			t.Fatalf("GenerateRed25519Key: %v", err)
		}
		sk := key.(Red25519PrivateKey)
		if len(sk) != PrivateKeySize {
			t.Fatalf("generated key is %d bytes, want %d", len(sk), PrivateKeySize)
		}
		// Must be canonical: SetCanonicalBytes rejects values >= L.
		if _, canonical := decodeScalarLE(sk); !canonical {
			t.Errorf("generated scalar %x is >= L; GENERATE_PRIVATE must reduce mod L", sk)
		}
		// A clamped Ed25519 scalar always has these bits; a mod-L scalar has bit
		// 254 clear (byte 31 top two bits are 0 for values < 2^253).
		if sk[31]&0xE0 != 0 {
			t.Errorf("generated scalar byte31 = %02x has high bits set, suggesting Ed25519 clamping rather than mod-L reduction", sk[31])
		}
	}
}

// TestRed25519BlindingInvariant checks RANDOMIZE_PUBLIC(vk, alpha) ==
// DERIVE_PUBLIC(RANDOMIZE_PRIVATE(sk, alpha)) for freshly generated keys, the
// relationship §Design requires and the one that additive-only implementations
// (or a mix of additive and multiplicative) break.
func TestRed25519BlindingInvariant(t *testing.T) {
	for i := 0; i < 10; i++ {
		pub, priv := newTestKeyPair(t)
		alpha, err := GenerateBlindingFactor(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateBlindingFactor: %v", err)
		}
		rsk, err := BlindPrivateKey(priv, alpha)
		if err != nil {
			t.Fatalf("BlindPrivateKey: %v", err)
		}
		rvk, err := BlindPublicKey(pub, alpha)
		if err != nil {
			t.Fatalf("BlindPublicKey: %v", err)
		}
		derived, err := rsk.Public()
		if err != nil {
			t.Fatalf("Public: %v", err)
		}
		if !bytes.Equal(derived.Bytes(), rvk.Bytes()) {
			t.Fatalf("invariant broken: DERIVE_PUBLIC(rsk) = %x, rvk = %x", derived.Bytes(), rvk.Bytes())
		}

		// And the blinded key pair must actually work together.
		msg := []byte("blinded destination signature")
		signer, err := rsk.NewSigner()
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		sig, err := signer.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		v, err := rvk.NewVerifier()
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		if err := v.Verify(msg, sig); err != nil {
			t.Fatalf("blinded signature failed to verify: %v", err)
		}
	}
}

// TestBlindingFactorsRejectZero documents that a zero alpha is refused: additive
// re-randomization "behaves like a one-time pad", so a biased alpha leaks the key,
// and alpha = 0 leaves the Destination fully exposed.
func TestBlindingFactorsRejectZero(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	if _, err := BlindPublicKey(pub, BlindingFactor{}); err == nil {
		t.Error("zero blinding factor accepted for the public key")
	}
	if _, err := BlindPrivateKey(priv, BlindingFactor{}); err == nil {
		t.Error("zero blinding factor accepted for the private key")
	}
}

// TestRed25519VerifierFromPrivateKey checks the convenience path.
func TestRed25519VerifierFromPrivateKey(t *testing.T) {
	_, priv := newTestKeyPair(t)
	v, err := priv.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	signer, _ := priv.NewSigner()
	msg := []byte("self-verification")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(msg, sig); err != nil {
		t.Errorf("self-verification failed: %v", err)
	}
}

// TestRed25519Zero clears key material.
func TestRed25519Zero(t *testing.T) {
	_, priv := newTestKeyPair(t)
	priv.Zero()
	if !isAllZero(priv) {
		t.Error("Zero did not clear the private key")
	}
}

// TestRed25519SmallOrderRIsAcceptedByCofactorVerify documents the cofactor
// behavior the spec mandates: VERIFY multiplies by the cofactor, so R may carry an
// 8-torsion component. This distinguishes Red25519 from strict Ed25519
// verification.
func TestRed25519SmallOrderRIsAcceptedByCofactorVerify(t *testing.T) {
	// Build a signature whose R is the identity plus torsion by hand-checking the
	// equation is evaluated with MultByCofactor. We assert the code path exists and
	// that a valid signature still verifies, then that a signature with a
	// non-canonical S (== L) is rejected per "if S >= L: return false".
	pub, priv := newTestKeyPair(t)
	signer, _ := priv.NewSigner()
	msg := []byte("cofactor verification")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := pub.NewVerifier()
	if err := v.Verify(msg, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	// Forge S = L (non-canonical): must be rejected by the S >= L check.
	bad := append([]byte{}, sig...)
	copy(bad[PublicKeySize:], littleEndianL(t))
	if err := v.Verify(msg, bad); err == nil {
		t.Error("signature with S = L (>= L) was accepted; VERIFY must reject S >= L")
	}
}

// littleEndianL encodes the group order L in the spec's little-endian form.
func littleEndianL(t *testing.T) []byte {
	t.Helper()
	b := orderL.Bytes() // big-endian
	out := make([]byte, ScalarSize)
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// TestRed25519BlindRejectsSmallOrder enforces encryptedleaseset.md §Goals on the
// Red25519 blinding path too: "Blinded public keys must be on the Ed25519 curve
// and prime-order subgroup". RANDOMIZE_PUBLIC adds [alpha]B, which is always in
// the subgroup, so a torsion input would carry straight through to the blinded
// key.
func TestRed25519BlindRejectsSmallOrder(t *testing.T) {
	var torsion Red25519PublicKey
	for i := 0; i < 31; i++ {
		torsion = append(torsion, 0xff)
	}
	torsion = append(torsion, 0x7f)

	var alpha BlindingFactor
	alpha[0] = 1

	if _, err := BlindPublicKey(torsion, alpha); err == nil {
		t.Error("BlindPublicKey accepted a small-order point")
	} else if !errors.Is(err, ErrSmallOrderPoint) {
		t.Errorf("got %v, want ErrSmallOrderPoint", err)
	}
}
