package tunnel

// Spec-layout tests for the AES tunnel layer cipher.
//
// These assert the *field offsets* of a tunnel message, which the pre-existing
// tests never checked: they compared lengths and self-inverse behaviour, so a
// whole-block 4-byte shift passed them happily.
//
// Expectations come from the Tunnel Message specification
// (https://i2p.net/en/docs/specs/tunnel-message/, "Tunnel Message (Encrypted)"):
//
//	bytes 0..3     Tunnel ID        4 bytes, cleartext, nonzero
//	bytes 4..19    IV               16 bytes
//	bytes 20..1027 Encrypted Data   1008 bytes
//	Total size: 1028 bytes
//
// and from Tunnel Implementation §Participant Processing, which fixes the
// double AES-256/ECB transform of the IV around the payload operation.

import (
	"bytes"
	"testing"
)

// fixedKeys builds deterministic layer and IV keys so a regression produces an
// observable change in the ciphertext.
func fixedKeys(t *testing.T) (layer, ivk *TunnelKey) {
	t.Helper()
	lb := make([]byte, 32)
	ib := make([]byte, 32)
	for i := range lb {
		lb[i] = byte(i + 1)
		ib[i] = byte(200 - i)
	}
	var err error
	if layer, err = NewTunnelKey(lb); err != nil {
		t.Fatalf("layer key: %v", err)
	}
	if ivk, err = NewTunnelKey(ib); err != nil {
		t.Fatalf("iv key: %v", err)
	}
	return layer, ivk
}

// TestTunnelMessageFieldOffsets asserts the offset constants themselves against
// the spec's byte table, so a drift is caught before the cipher is exercised.
func TestTunnelMessageFieldOffsets(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"TunnelMessageSize", TunnelMessageSize, 1028},
		{"TunnelIDSize", TunnelIDSize, 4},
		{"TunnelIVOffset", TunnelIVOffset, 4},
		{"TunnelIVSize", TunnelIVSize, 16},
		{"TunnelPayloadOffset", TunnelPayloadOffset, 20},
		{"TunnelPayloadSize", TunnelPayloadSize, 1008},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d (tunnel-message spec field table)", c.name, c.got, c.want)
		}
	}
	// The regions must tile the block exactly: 4 + 16 + 1008 == 1028.
	if TunnelIDSize+TunnelIVSize+TunnelPayloadSize != TunnelMessageSize {
		t.Errorf("field sizes %d+%d+%d != block size %d",
			TunnelIDSize, TunnelIVSize, TunnelPayloadSize, TunnelMessageSize)
	}
	// The payload must reach the end of the block: there is no unencrypted tail.
	if TunnelPayloadOffset+TunnelPayloadSize != TunnelMessageSize {
		t.Errorf("payload region ends at %d, want %d (no unencrypted tail)",
			TunnelPayloadOffset+TunnelPayloadSize, TunnelMessageSize)
	}
	if len(TunnelData{}) != TunnelMessageSize {
		t.Errorf("TunnelData is %d bytes, want %d", len(TunnelData{}), TunnelMessageSize)
	}
}

// TestAESEncryptor_PayloadOnlyLayout checks the 1008-byte input form: the IV
// must land at bytes 4..19 and the payload at bytes 20..1027. A 4-byte shift
// would put the IV at bytes 0..15 instead.
func TestAESEncryptor_PayloadOnlyLayout(t *testing.T) {
	layer, ivk := fixedKeys(t)
	enc, err := NewAESEncryptor(*layer, *ivk)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}

	payload := make([]byte, TunnelPayloadSize)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	rec, err := enc.Encrypt(payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(rec) != TunnelMessageSize {
		t.Fatalf("record is %d bytes, want %d", len(rec), TunnelMessageSize)
	}

	if bytes.Equal(rec[TunnelIVOffset:TunnelIVOffset+TunnelIVSize], make([]byte, TunnelIVSize)) {
		t.Error("IV region bytes 4..19 are all zero; expected the random IV there")
	}
	if bytes.Equal(rec[TunnelPayloadOffset:], payload) {
		t.Error("payload region bytes 20..1027 is unencrypted")
	}

	got, err := enc.Decrypt(rec)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("round trip did not restore the 1008-byte payload")
	}
}

// TestAESEncryptor_FullRecordKeepsTunnelIDCleartext is the regression test for
// the off-by-4 defect: given a caller-supplied 1028-byte record, bytes 0..3 are
// the cleartext tunnel ID and must survive untouched, while the whole payload
// region including its final four bytes must be processed.
func TestAESEncryptor_FullRecordKeepsTunnelIDCleartext(t *testing.T) {
	layer, ivk := fixedKeys(t)
	enc, err := NewAESEncryptor(*layer, *ivk)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}

	var rec TunnelData
	tunnelID := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	copy(rec[:TunnelIDSize], tunnelID)
	for i := 0; i < TunnelIVSize; i++ {
		rec[TunnelIVOffset+i] = byte(0x10 + i)
	}
	for i := TunnelPayloadOffset; i < TunnelMessageSize; i++ {
		rec[i] = byte(i%199) + 1 // deliberately nonzero, so a pass-through tail is detectable
	}

	out, err := enc.Encrypt(rec[:])
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The tunnel ID is framing, not a cryptographic value: carried through.
	if !bytes.Equal(out[:TunnelIDSize], tunnelID) {
		t.Errorf("tunnel ID bytes 0..3 = %x, want %x (must be preserved cleartext)",
			out[:TunnelIDSize], tunnelID)
	}

	// The IV region must have been transformed by the IV key, not left as-is.
	if bytes.Equal(out[TunnelIVOffset:TunnelIVOffset+TunnelIVSize], rec[TunnelIVOffset:TunnelIVOffset+TunnelIVSize]) {
		t.Error("IV region bytes 4..19 unchanged; the AES-256/ECB IV transform was not applied there")
	}

	// The whole payload region must be transformed. A single ciphertext byte can
	// legitimately be zero, so assert on the region as a whole: because the
	// plaintext tail here is deliberately nonzero, an unprocessed tail (the old
	// 16..1024 window, which left 1024..1027 as zeros) shows up verbatim.
	if bytes.Equal(out[TunnelPayloadOffset:], rec[TunnelPayloadOffset:]) {
		t.Error("payload region bytes 20..1027 passed through unencrypted")
	}
	if bytes.Equal(out[TunnelMessageSize-16:], rec[TunnelMessageSize-16:]) {
		t.Errorf("bytes %d..%d are identical to the plaintext; the payload tail is not encrypted",
			TunnelMessageSize-16, TunnelMessageSize-1)
	}
	if bytes.Equal(out[TunnelMessageSize-TunnelIDSize:], make([]byte, TunnelIDSize)) {
		t.Error("bytes 1024..1027 are all zero; the final 4 payload bytes must be encrypted")
	}

	// Decrypt must hand back exactly the payload region.
	got, err := enc.Decrypt(out)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(got) != TunnelPayloadSize {
		t.Fatalf("Decrypt returned %d bytes, want %d", len(got), TunnelPayloadSize)
	}
	if !bytes.Equal(got, rec[TunnelPayloadOffset:]) {
		t.Error("Decrypt did not restore bytes 20..1027 of the original record")
	}
}

// TestAESEncryptor_IVDoubleTransformIsSymmetric pins the §Participant Processing
// rule that the IV is transformed with the IV key both *before* and *after* the
// payload operation: "encrypts the received IV with AES256/ECB using their IV key
// to determine the current IV, uses that IV with the participant's layer key to
// encrypt the data, encrypts the current IV with AES256/ECB using their IV key
// again".
//
// The observable consequence: Encrypt forwards the IV through two ECB steps, and
// Decrypt runs the inverse transform in the mirrored order, so a full
// Encrypt/Decrypt cycle must restore the payload exactly. A single-transform
// implementation would shift the IV by one ECB step and corrupt the payload.
func TestAESEncryptor_IVDoubleTransformIsSymmetric(t *testing.T) {
	layer, ivk := fixedKeys(t)
	enc, err := NewAESEncryptor(*layer, *ivk)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}

	var rec TunnelData
	copy(rec[:TunnelIDSize], []byte{0x00, 0x00, 0x13, 0x37})
	for i := 0; i < TunnelIVSize; i++ {
		rec[TunnelIVOffset+i] = byte(0xA0 + i)
	}
	for i := TunnelPayloadOffset; i < TunnelMessageSize; i++ {
		rec[i] = byte(i * 3)
	}
	origIV := append([]byte{}, rec[TunnelIVOffset:TunnelIVOffset+TunnelIVSize]...)

	out, err := enc.Encrypt(rec[:])
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The forwarded IV must have moved: two ECB applications of the IV key.
	forwardedIV := out[TunnelIVOffset : TunnelIVOffset+TunnelIVSize]
	if bytes.Equal(forwardedIV, origIV) {
		t.Error("forwarded IV equals the received IV; the IV transform did not run")
	}

	// Decrypt inverts the double transform and must recover the payload.
	got, err := enc.Decrypt(out)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, rec[TunnelPayloadOffset:]) {
		t.Error("payload not restored; the IV transform is not symmetric")
	}
}
