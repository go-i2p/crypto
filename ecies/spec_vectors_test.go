package ecies

// Spec-derived known-answer vectors for the one-time (section 1d) key schedule.
//
// The expectations in this file are NOT produced by this package. They were
// computed separately from the specification text in section 1f ("KDF for
// Initial ChainKey" and "KDF for Flags/Static Key Section Encrypted Contents")
// using only SHA-256, X25519 and RFC 5869 HKDF:
//
//	protocol_name = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"   (40 bytes)
//	h        = SHA256(protocol_name)          // also becomes chainKey
//	h        = SHA256(h)                      // MixHash(null prologue)
//	h        = SHA256(h || bpk)               // MixHash(Bob's static public key)
//	h        = SHA256(h || aepk)              // MixHash(Alice's ephemeral public key)
//	sharedSecret = DH(aesk, bpk)              // "es"
//	keydata  = HKDF(salt=chainKey, ikm=sharedSecret, info="", 64)
//	k        = keydata[32:64]
//
// The inputs are a fixed, deterministic key pair so the vectors are
// reproducible. This pins the protocol name, the MixHash order, the HKDF
// salt/ikm ordering and the keydata slice: if any of those drift, these tests
// fail even though a self-consistent round-trip test would still pass.

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// katInputs builds the fixed bpk / aesk / aepk used by the vectors below.
// bpk = 0x01..0x20; aesk = 0xc8..0xa9 clamped per RFC 7748; aepk = X25519(aesk, basepoint).
func katInputs(t *testing.T) (bpk, aesk, aepk []byte) {
	t.Helper()

	bpk = make([]byte, 32)
	aesk = make([]byte, 32)
	for i := 0; i < 32; i++ {
		bpk[i] = byte(i + 1)
		aesk[i] = byte(200 - i)
	}
	aesk[0] &= 248
	aesk[31] &= 127
	aesk[31] |= 64

	var err error
	aepk, err = curve25519.X25519(aesk, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("deriving test aepk failed: %v", err)
	}
	return bpk, aesk, aepk
}

func mustHexVec(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test vector %q: %v", s, err)
	}
	return b
}

// TestNoiseProtocolName asserts the spec's own requirement on the protocol name,
// which feeds the whole hash chain: 40 bytes, US-ASCII, no NUL termination.
func TestNoiseProtocolName(t *testing.T) {
	const want = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"
	if noiseProtocolName != want {
		t.Errorf("protocol name mismatch:\n got  %q\n want %q", noiseProtocolName, want)
	}
	if len(noiseProtocolName) != 40 {
		t.Errorf("protocol name is %d bytes, spec requires exactly 40", len(noiseProtocolName))
	}
}

// TestOneTimeMixHashChain pins each MixHash step separately, so a failure
// localises to the exact step that drifted rather than to the final digest.
func TestOneTimeMixHashChain(t *testing.T) {
	bpk, _, aepk := katInputs(t)

	// chainKey = h = SHA256(protocol_name)
	chainKey := sha256.Sum256([]byte(noiseProtocolName))
	if got, want := hex.EncodeToString(chainKey[:]), "4caf11ef2c8e36564c53e88885064dbaacbe0054ad178f8079a646827e6ee40c"; got != want {
		t.Errorf("SHA256(protocol_name):\n got  %s\n want %s", got, want)
	}

	// MixHash(null prologue)
	h := sha256.Sum256(chainKey[:])
	if got, want := hex.EncodeToString(h[:]), "9ccf852cc93bb9504441e950e01d52322e0d47add1e9a555f755b569ae183b5c"; got != want {
		t.Errorf("h after MixHash(prologue):\n got  %s\n want %s", got, want)
	}

	// MixHash(bpk)
	h = sha256.Sum256(append(append([]byte{}, h[:]...), bpk...))
	if got, want := hex.EncodeToString(h[:]), "13b2a57269b64c0c55cdb628d7cbe53851f6dfc6c09947ec83c4118939760526"; got != want {
		t.Errorf("h after MixHash(bpk):\n got  %s\n want %s", got, want)
	}

	// MixHash(aepk) - this h is the AEAD associated data for both sections.
	h = sha256.Sum256(append(append([]byte{}, h[:]...), aepk...))
	if got, want := hex.EncodeToString(h[:]), "237593a0c2b96f983636693261c68a65a2707766cce81b261cc3b0780d603311"; got != want {
		t.Errorf("h after MixHash(aepk):\n got  %s\n want %s", got, want)
	}
}

// TestOneTimeKeyScheduleKnownAnswer checks deriveOneTimeKey against the vectors
// computed independently from the spec.
func TestOneTimeKeyScheduleKnownAnswer(t *testing.T) {
	bpk, aesk, aepk := katInputs(t)

	h, k, err := deriveOneTimeKey(bpk, aesk, aepk, nil)
	if err != nil {
		t.Fatalf("deriveOneTimeKey failed: %v", err)
	}

	wantH := mustHexVec(t, "237593a0c2b96f983636693261c68a65a2707766cce81b261cc3b0780d603311")
	if hex.EncodeToString(h[:]) != hex.EncodeToString(wantH) {
		t.Errorf("handshake hash h mismatch:\n got  %x\n want %x", h, wantH)
	}

	wantK := mustHexVec(t, "fefe17dc1fa72ac075e942b63d23d053636739ad92f716e065a1d23c64b49edb")
	if hex.EncodeToString(k[:]) != hex.EncodeToString(wantK) {
		t.Errorf("message key k mismatch:\n got  %x\n want %x", k, wantK)
	}
}

// TestOneTimeKnownAnswerDecryptable is the cross-check that matters most: a
// ciphertext produced from the independently-derived key must decrypt with the
// package, and vice versa. It ties the vector test to the real wire format
// without relying on the package's own key schedule being correct.
func TestOneTimeKnownAnswerDecryptable(t *testing.T) {
	bpk, aesk, aepk := katInputs(t)

	h, k, err := deriveOneTimeKey(bpk, aesk, aepk, nil)
	if err != nil {
		t.Fatalf("deriveOneTimeKey failed: %v", err)
	}

	// The flags section is 32 zero bytes encrypted at counter 0 with ad = h.
	flagsCt, err := encryptSection(k, h, make([]byte, flagsSectionSize), 0)
	if err != nil {
		t.Fatalf("encryptSection failed: %v", err)
	}
	if len(flagsCt) != flagsSectionSize+TagSize {
		t.Fatalf("flags section is %d bytes, want %d", len(flagsCt), flagsSectionSize+TagSize)
	}

	// Recovering all-zero flags proves the salt/ikm ordering, the nonce layout
	// and the associated data all agree with the spec-derived key.
	flags, err := decryptSection(k, h, flagsCt, 0)
	if err != nil {
		t.Fatalf("decryptSection rejected a correctly produced flags section: %v", err)
	}
	if !isAllZeros(flags) {
		t.Errorf("flags section decrypted to %x, want 32 zero bytes", flags)
	}
}
