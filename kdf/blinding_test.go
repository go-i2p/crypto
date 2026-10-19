package kdf

// Tests for the I2P-conformant destination-blinding KDF
// ([DeriveBlindingFactorI2P]). Destination blinding is used by I2P to hide the
// relationship between a destination and its owner (see
// https://i2p.net/en/docs/specs/cryptography/).

import (
	"encoding/hex"
	"testing"
	"time"
)

// TestDeriveBlindingFactorI2P is a known-answer test for the I2P-conformant
// destination-blinding KDF. The expected alphas are computed from the reference
// algorithm in net.i2p.crypto.Blinding.generateAlpha:
//
//	salt = SHA256("I2PGenerateAlpha" || spk || sigtypeIn(2 BE) || 0x000b)
//	ikm  = yyyyMMdd(GMT) || secretUTF8
//	out  = HKDF-SHA256(salt, ikm, "i2pblinding1", 64)
//	alpha = 64-byte little-endian out reduced mod L, encoded 32-byte LE
//
// with spk = 0x00..0x1f. This locks the implementation to the spec algorithm so
// a future change to the salt/info/date-format is caught.
func TestDeriveBlindingFactorI2P(t *testing.T) {
	spk := make([]byte, 32)
	for i := range spk {
		spk[i] = byte(i)
	}

	cases := []struct {
		name   string
		secret string
		date   string // yyyyMMdd (GMT)
		want   string // 32-byte alpha, hex
	}{
		{"empty-secret-2025-11-24", "", "20251124", "447142813ed2fde0b81b135adc1888c6360715ad15883725ae0a903db38eea06"},
		{"secret-2025-11-24", "hunter2", "20251124", "dd1b9ad27521978f52ec450f4099fc9e9ce6e105f1984f29371b28e47f2e1d0e"},
		{"empty-secret-2024-01-01", "", "20240101", "a412deb025261296f777e64facc5834931e215fde25264a3c1047687fdf2c605"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tv, err := time.Parse("20060102", tc.date)
			if err != nil {
				t.Fatalf("bad date: %v", err)
			}
			got, err := DeriveBlindingFactorI2P(spk, tc.secret, SigTypeEdDSASha512Ed25519, tv)
			if err != nil {
				t.Fatalf("DeriveBlindingFactorI2P: %v", err)
			}
			if hex.EncodeToString(got[:]) != tc.want {
				t.Errorf("alpha mismatch:\n got %x\nwant %s", got, tc.want)
			}
		})
	}
}

// TestDeriveBlindingFactorI2PValidation checks input validation.
func TestDeriveBlindingFactorI2PValidation(t *testing.T) {
	spk := make([]byte, 32)
	tv := time.Unix(0, 0).UTC()

	if _, err := DeriveBlindingFactorI2P(make([]byte, 31), "", SigTypeEdDSASha512Ed25519, tv); err == nil {
		t.Error("expected error for 31-byte spk")
	}
	if _, err := DeriveBlindingFactorI2P(spk, "", 99, tv); err == nil {
		t.Error("expected error for unsupported sig type")
	}
	// RedDSA (11) as the input type is accepted.
	if _, err := DeriveBlindingFactorI2P(spk, "", SigTypeRedDSASha512Ed25519, tv); err != nil {
		t.Errorf("RedDSA sigtype should be accepted: %v", err)
	}
}
