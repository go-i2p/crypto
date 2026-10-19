package tunnel

// Known-answer and round-trip tests for the Tunnel-Creation-ECIES build-record
// primitives.
//
// The expectations in this file are computed from the specification text
// (https://i2p.net/en/docs/specs/tunnel-creation-ecies/) using only SHA-256,
// RFC 5869 HKDF, and RFC 7539 ChaCha20/Poly1305 - NOT by this package. They pin
// the protocol name, the padded-hash initializer, the MixHash order, the
// HKDF salt/ikm ordering, the reply/layer KDF chain (including the OBEP branch),
// and the nonce/IV layout. If any of those drift, these tests fail even though a
// self-consistent round-trip would still pass.

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestBuildProtocolName pins the spec's own requirement on the protocol name.
func TestBuildProtocolName(t *testing.T) {
	const want = "Noise_N_25519_ChaChaPoly_SHA256"
	if buildProtocolName != want {
		t.Errorf("protocol name = %q, want %q", buildProtocolName, want)
	}
	// Spec: "(31 bytes, US-ASCII encoded, no NULL termination)" - and it is the
	// PADDING of that 31-byte name to 32 bytes, not a hash, that initializes h.
	if len(buildProtocolName) != 31 {
		t.Errorf("protocol name is %d bytes, spec requires 31", len(buildProtocolName))
	}
}

// TestNewBuildNoiseState pins the "KDF for Initial ck and h" step.
func TestNewBuildNoiseState(t *testing.T) {
	s := NewBuildNoiseState()

	// ck = protocol_name || 0 (padded, NOT hashed).
	ck := s.ChainKey()
	wantCK := "4e6f6973655f4e5f32353531395f436861436861506f6c795f53484132353600"
	if got := hex.EncodeToString(ck[:]); got != wantCK {
		t.Errorf("initial ck = %s, want %s", got, wantCK)
	}
	// h = SHA256(padded) after MixHash(null prologue).
	h := s.Hash()
	wantH := "694d52445a27d9adfad29c7632395dc1e4354c69b4f92eac8a1ee46a9ed21554"
	if got := hex.EncodeToString(h[:]); got != wantH {
		t.Errorf("initial h = %s, want %s", got, wantH)
	}
}

// TestBuildMixKey pins the Noise MixKey step: HKDF(salt=ck, ikm=sharedSecret,
// info="", 64), with ck = keydata[0:32] and k = keydata[32:64].
func TestBuildMixKey(t *testing.T) {
	s := NewBuildNoiseState()
	ss := make([]byte, 32)
	for i := range ss {
		ss[i] = byte(i)
	}

	k, err := s.MixKey(ss)
	if err != nil {
		t.Fatalf("MixKey: %v", err)
	}

	wantK := "39cd09d5a50fb45469814a81c6f6fa240bccae111a4b48326142042cdedc9671"
	if got := hex.EncodeToString(k[:]); got != wantK {
		t.Errorf("MixKey k = %s, want %s", got, wantK)
	}
	ck := s.ChainKey()
	wantCK := "0f9be960522b1bfeb7473a75a46496c5704f05c075dd97062a8e137d724fbfda"
	if got := hex.EncodeToString(ck[:]); got != wantCK {
		t.Errorf("MixKey ck = %s, want %s", got, wantCK)
	}
}

// TestBuildMixHashOrder pins that the hop static key is mixed before the sender
// ephemeral key, matching the spec's MixHash(hepk) then MixHash(sepk).
func TestBuildMixHashOrder(t *testing.T) {
	s := NewBuildNoiseState()

	hepk := make([]byte, 32)
	sepk := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hepk[i] = byte(0xa0 + i)
		sepk[i] = byte(0x10 + i)
	}
	s.MixHash(hepk)
	s.MixHash(sepk)

	h := s.Hash()
	want := "770e21dfafaefc7d26613ddb8e8cf3ce793e444608a0631746ccbb888492c2ac"
	if got := hex.EncodeToString(h[:]); got != want {
		t.Errorf("h after MixHash(hepk||sepk) = %s, want %s", got, want)
	}
}

// TestDeriveBuildReplyKeysNonOBEP pins the reply/layer KDF chain for a
// non-OBEP hop, where the left half of the layer key output is the IV key.
func TestDeriveBuildReplyKeysNonOBEP(t *testing.T) {
	s := seedStateAfterMixKey(t)

	keys, err := DeriveBuildReplyKeys(s, false)
	if err != nil {
		t.Fatalf("DeriveBuildReplyKeys: %v", err)
	}

	checkHex(t, "replyKey", keys.ReplyKey[:], "d251fd428a99666ed3471d10cf69d892020bb7e7ffb0616cccea6fb41ba3e5a6")
	checkHex(t, "layerKey", keys.LayerKey[:], "c2619d5e2d163799a03630995f542ec4b92c109f59fd9a6b074755d75803abbc")
	checkHex(t, "ivKey", keys.IVKey[:], "ffda20f0d1ae64d2816da9044f83a7508212b6bd3e10f152c1e949d6026772dc")
}

// TestDeriveBuildReplyKeysOBEP pins the OBEP branch, which adds the
// TunnelLayerIVKey and RGarlicKeyAndTag steps.
func TestDeriveBuildReplyKeysOBEP(t *testing.T) {
	s := seedStateAfterMixKey(t)

	keys, err := DeriveBuildReplyKeys(s, true)
	if err != nil {
		t.Fatalf("DeriveBuildReplyKeys: %v", err)
	}

	checkHex(t, "replyKey", keys.ReplyKey[:], "d251fd428a99666ed3471d10cf69d892020bb7e7ffb0616cccea6fb41ba3e5a6")
	checkHex(t, "layerKey", keys.LayerKey[:], "c2619d5e2d163799a03630995f542ec4b92c109f59fd9a6b074755d75803abbc")
	// The OBEP IV key differs from the non-OBEP one - the whole point of the
	// branch.
	checkHex(t, "ivKey(OBEP)", keys.IVKey[:], "f00de82bfa34e609a6dd7b3e76d800c8768ce3735da2aa33c20097724683f439")
	checkHex(t, "garlicReplyKey", keys.GarlicReplyKey[:], "0790180ae191b0adda983a9477334dc01a456a4893db3b6ea1e2f2c9ace8419e")
	checkHex(t, "garlicReplyTag", keys.GarlicReplyTag[:], "c1f387a927f6829c")
}

// TestBuildRecordSizes pins the sizes the spec fixes for build records.
func TestBuildRecordSizes(t *testing.T) {
	// Short (current, 0.9.51+).
	// The complete on-wire short record is 218 bytes for BOTH request and reply,
	// but they reach it differently: a request carries a 16-byte identity hash
	// and a 32-byte ephemeral key before the 154-byte ciphertext, while a reply
	// has no cleartext prefix.
	if ShortBuildRequestSize != 154 || ShortBuildReplySize != 202 || ShortBuildRecordSize != 218 {
		t.Errorf("short record sizes = %d/%d/%d, want 154/202/218",
			ShortBuildRequestSize, ShortBuildReplySize, ShortBuildRecordSize)
	}
	if ShortBuildRequestEncryptedSize != 170 {
		t.Errorf("short request AEAD output = %d, want 170 (154+16)", ShortBuildRequestEncryptedSize)
	}
	if ShortBuildReplyEncryptedSize != 218 {
		t.Errorf("short reply AEAD output = %d, want 218 (202+16)", ShortBuildReplyEncryptedSize)
	}
	// Wire-record arithmetic from the spec's byte tables.
	if TruncatedIdentityHashSize+EphemeralPublicKeySize+ShortBuildRequestEncryptedSize != ShortBuildRecordSize {
		t.Error("16 + 32 + request ciphertext must equal the 218-byte wire record")
	}
	if ShortBuildReplyEncryptedSize != ShortBuildRecordSize {
		t.Error("short reply ciphertext is the whole 218-byte record (no cleartext prefix)")
	}
	// Long (deprecated, 0.9.48): 16 + 32 + 480 = 528, reply 512 + 16 = 528.
	if LongBuildRequestSize != 464 || LongBuildReplySize != 512 || LongBuildRecordSize != 528 {
		t.Errorf("long record sizes = %d/%d/%d, want 464/512/528",
			LongBuildRequestSize, LongBuildReplySize, LongBuildRecordSize)
	}
	if TruncatedIdentityHashSize+EphemeralPublicKeySize+LongBuildRequestEncryptedSize != LongBuildRecordSize {
		t.Error("16 + 32 + long request ciphertext must equal the 528-byte wire record")
	}
	if MaxBuildRecords != 8 {
		t.Errorf("MaxBuildRecords = %d, want 8 (record number 0-7)", MaxBuildRecords)
	}
}

// TestEncryptBuildRequestKnownAnswer checks the AEAD over a serialized request
// record against the independently derived key, hash and nonce.
func TestEncryptBuildRequestKnownAnswer(t *testing.T) {
	s := NewBuildNoiseState()

	hepk := make([]byte, 32)
	sepk := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hepk[i] = byte(0xa0 + i)
		sepk[i] = byte(0x10 + i)
	}
	// Use the fixed 32-byte "DH output" the vectors were computed with by
	// driving MixKey directly rather than a real X25519 result.
	ss := make([]byte, 32)
	for i := range ss {
		ss[i] = byte(i)
	}
	s.MixHash(hepk)
	s.MixHash(sepk)

	k, err := s.MixKey(ss)
	if err != nil {
		t.Fatalf("MixKey: %v", err)
	}
	ad := s.Hash()

	pt := make([]byte, ShortBuildRequestSize)
	for i := range pt {
		pt[i] = byte(i)
	}

	ct, err := sealBuildRecord(k, ad, pt, 0)
	if err != nil {
		t.Fatalf("sealBuildRecord: %v", err)
	}
	if len(ct) != ShortBuildRequestSize+BuildTagSize {
		t.Fatalf("ciphertext length = %d, want %d", len(ct), ShortBuildRequestSize+BuildTagSize)
	}

	want := mustHex(t, "f9b66800521cbe4029c8f4265f4d829a92aa18d149e9f8c8adec4abd5521241b"+
		"f5627a9eceb8759a0f9b7c64be1571059956e31ee7d9c8c796f8f6b6be656276"+
		"ff720b461be709b082ede0d3ce909c62e720ed35a35565ed3c904de12862bb0c"+
		"4f3178177d99574c32ecd5a5c2ed684faacf93a72cd5d2dbf47edb9903a687c9"+
		"b80a10c592dfde69883b42cb8ec1d6c09bff4d6d03c3038ce1d1a2eb874b2285"+
		"7ed8e95d83ee8330566d")
	if !bytes.Equal(ct, want) {
		t.Errorf("request ciphertext mismatch:\n got  %x\n want  %x", ct, want)
	}

	// The tag must round-trip back through the open path.
	back, err := openBuildRecord(k, ad, ct, 0)
	if err != nil {
		t.Fatalf("openBuildRecord: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Error("openBuildRecord did not recover the plaintext")
	}
}

// TestOwnBuildReplyKnownAnswer pins that the hop's own reply uses the record
// number as the nonce (n = 3 here), unlike the deprecated long-record form which
// always used n = 0.
func TestOwnBuildReplyKnownAnswer(t *testing.T) {
	s := seedStateAfterMixKey(t)
	keys, err := DeriveBuildReplyKeys(s, false)
	if err != nil {
		t.Fatalf("DeriveBuildReplyKeys: %v", err)
	}

	ad := [32]byte{}
	copy(ad[:], mustHex(t, "770e21dfafaefc7d26613ddb8e8cf3ce793e444608a0631746ccbb888492c2ac"))
	pt := make([]byte, ShortBuildReplySize)
	for i := range pt {
		pt[i] = byte(i)
	}

	ct, err := EncryptOwnBuildReply(keys.ReplyKey, ad, 3, pt)
	if err != nil {
		t.Fatalf("EncryptOwnBuildReply: %v", err)
	}
	// A short reply has no cleartext prefix, so its AEAD output is the entire
	// 218-byte wire record.
	if len(ct) != ShortBuildRecordSize {
		t.Fatalf("reply ciphertext = %d bytes, want %d", len(ct), ShortBuildRecordSize)
	}

	want := mustHex(t, "9211e978a1c8a10f204bb2d472c3981ceab2b4c1635a9d03c3b91dc01bf48812"+
		"e70d4e26a8e2e1de412605344c9846f424828b6442b34cd0ff8f7d8f650f7b8f"+
		"bb8721aea991c346a4ee3ce8340a629c81c49535a3392098a1b68707f19339f2"+
		"a6e748a453fda1b44d8e47154aa9e2c05f16b2c06763276e8816c6e17aba7d28"+
		"9c910a6ebb80689d45a2e968014ccc1bb6e3263e170bfbce0d5b60ce8b96e3cf"+
		"ead8b6136e6f9e29b093fa2d3b3e70b25771c3907cea9eee572ce14dbf069f49"+
		"2c863f413ee574853ca8b6277886137a51fd2ae8fbce555c4dff")
	if !bytes.Equal(ct, want) {
		t.Errorf("own reply ciphertext mismatch:\n got  %x\n want  %x", ct, want)
	}

	// Round-trip through the decrypt path.
	back, err := DecryptOwnBuildReply(keys.ReplyKey, ad, 3, ct)
	if err != nil {
		t.Fatalf("DecryptOwnBuildReply: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Error("reply round trip mismatch")
	}

	// A different record number must produce a different ciphertext.
	other, err := EncryptOwnBuildReply(keys.ReplyKey, ad, 4, pt)
	if err != nil {
		t.Fatalf("EncryptOwnBuildReply(n=4): %v", err)
	}
	if bytes.Equal(other, ct) {
		t.Error("record number is not affecting the nonce")
	}
}

// TestObfuscateOtherBuildRecordKnownAnswer pins the raw ChaCha20 stream used for
// the other records: unauthenticated, record number in IV byte 4.
func TestObfuscateOtherBuildRecordKnownAnswer(t *testing.T) {
	s := seedStateAfterMixKey(t)
	keys, err := DeriveBuildReplyKeys(s, false)
	if err != nil {
		t.Fatalf("DeriveBuildReplyKeys: %v", err)
	}

	record := make([]byte, ShortBuildRecordSize)
	for i := range record {
		record[i] = byte(i)
	}

	out, err := ObfuscateOtherBuildRecord(keys.ReplyKey, 3, record)
	if err != nil {
		t.Fatalf("ObfuscateOtherBuildRecord: %v", err)
	}
	if len(out) != len(record) {
		t.Fatalf("stream output length = %d, want %d (no tag, no padding)", len(out), len(record))
	}

	want := mustHex(t, "55ceeec5cacbf09c9dfa5d3d01aeee4136767d3bf6e0929cea84853bc1f24f4e")
	if !bytes.Equal(out[:32], want) {
		t.Errorf("stream prefix mismatch:\n got  %x\n want  %x", out[:32], want)
	}

	// XOR stream: applying it twice must restore the record.
	back, err := ObfuscateOtherBuildRecord(keys.ReplyKey, 3, out)
	if err != nil {
		t.Fatalf("ObfuscateOtherBuildRecord (undo): %v", err)
	}
	if !bytes.Equal(back, record) {
		t.Error("ObfuscateOtherBuildRecord is not self-inverse")
	}

	// Out-of-range record numbers must be rejected, not wrapped.
	if _, err := ObfuscateOtherBuildRecord(keys.ReplyKey, 8, record); err == nil {
		t.Error("record number 8 accepted, want rejection (spec allows 0-7)")
	}
}

// TestBuildRequestRoundTrip runs a full sender/hop exchange with real X25519
// keys, including the MixHash(ciphertext) that feeds the reply KDF.
func TestBuildRequestRoundTrip(t *testing.T) {
	hopPriv := fixedScalar(1)
	hopPub, err := curve25519.X25519(hopPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("hop key derivation: %v", err)
	}
	senderPriv := fixedScalar(2)
	senderPub, err := curve25519.X25519(senderPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("sender key derivation: %v", err)
	}

	pt := make([]byte, ShortBuildRequestSize)
	for i := range pt {
		pt[i] = byte(i * 7)
	}

	sendState := NewBuildNoiseState()
	ct, err := EncryptBuildRequest(sendState, hopPub, senderPriv, senderPub, pt)
	if err != nil {
		t.Fatalf("EncryptBuildRequest: %v", err)
	}
	if len(ct) != ShortBuildRequestEncryptedSize {
		t.Fatalf("ciphertext = %d bytes, want %d (154+16; the 48-byte cleartext prefix is the caller's)",
			len(ct), ShortBuildRequestEncryptedSize)
	}

	hopState := NewBuildNoiseState()
	got, err := DecryptBuildRequest(hopState, hopPriv, senderPub, ct)
	if err != nil {
		t.Fatalf("DecryptBuildRequest: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("round trip mismatch")
	}

	// Both sides must land on the same chaining key and hash, so the reply KDF
	// produces identical keys on the creator and the hop.
	if sendState.ChainKey() != hopState.ChainKey() {
		t.Error("chaining keys diverged after request encryption/decryption")
	}
	if sendState.Hash() != hopState.Hash() {
		t.Error("handshake hashes diverged after request encryption/decryption")
	}

	senderKeys, err := DeriveBuildReplyKeys(sendState, false)
	if err != nil {
		t.Fatalf("DeriveBuildReplyKeys(sender): %v", err)
	}
	hopKeys, err := DeriveBuildReplyKeys(hopState, false)
	if err != nil {
		t.Fatalf("DeriveBuildReplyKeys(hop): %v", err)
	}
	if senderKeys.ReplyKey != hopKeys.ReplyKey || senderKeys.LayerKey != hopKeys.LayerKey ||
		senderKeys.IVKey != hopKeys.IVKey {
		t.Error("reply/layer keys diverged between creator and hop")
	}

	// The hop encrypts its own reply with ad = h from the build request; the
	// creator decrypts with the same h, which both sides reached above.
	reply := make([]byte, ShortBuildReplySize)
	for i := range reply {
		reply[i] = byte(i)
	}
	ad := hopState.Hash()
	rct, err := EncryptOwnBuildReply(hopKeys.ReplyKey, ad, 0, reply)
	if err != nil {
		t.Fatalf("EncryptOwnBuildReply: %v", err)
	}
	back, err := DecryptOwnBuildReply(senderKeys.ReplyKey, sendState.Hash(), 0, rct)
	if err != nil {
		t.Fatalf("DecryptOwnBuildReply: %v", err)
	}
	if !bytes.Equal(back, reply) {
		t.Fatal("reply round trip mismatch")
	}
}

// TestBuildRequestUniqueEphemerals documents the spec's requirement that a
// repeated ephemeral key across two records to the same hop is detectable: the
// AEAD must produce different ciphertext only when the ephemeral differs.
func TestBuildRequestNonceIsZeroForRequest(t *testing.T) {
	s := seedStateAfterMixKey(t)
	k := s.ChainKey() // arbitrary but fixed
	ad := s.Hash()

	pt := make([]byte, ShortBuildRequestSize)
	a, err := sealBuildRecord(k, ad, pt, 0)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	b, err := sealBuildRecord(k, ad, pt, 1)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("counter is not affecting the request nonce")
	}
}

// --- helpers ---

// seedStateAfterMixKey builds a state whose chaining key matches the vector
// chain: initial state, MixHash(hepk||sepk), MixKey(fixed ss).
func seedStateAfterMixKey(t *testing.T) *BuildNoiseState {
	t.Helper()
	s := NewBuildNoiseState()
	hepk := make([]byte, 32)
	sepk := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hepk[i] = byte(0xa0 + i)
		sepk[i] = byte(0x10 + i)
	}
	s.MixHash(hepk)
	s.MixHash(sepk)
	ss := make([]byte, 32)
	for i := range ss {
		ss[i] = byte(i)
	}
	if _, err := s.MixKey(ss); err != nil {
		t.Fatalf("MixKey: %v", err)
	}
	return s
}

func checkHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if g := hex.EncodeToString(got); g != want {
		t.Errorf("%s = %s, want %s", name, g, want)
	}
}

// fixedScalar returns a valid clamped X25519 scalar derived from seed.
func fixedScalar(seed byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i+1) ^ seed
	}
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}
