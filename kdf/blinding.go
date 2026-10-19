package kdf

import (
	"crypto/sha256"
	"time"

	"filippo.io/edwards25519"

	"github.com/samber/oops"
)

// SigType codes used by the I2P blinding KDF salt (see net.i2p.crypto.SigType).
const (
	// SigTypeEdDSASha512Ed25519 is the standard Ed25519 signing type (code 7).
	SigTypeEdDSASha512Ed25519 uint16 = 7
	// SigTypeRedDSASha512Ed25519 is the blinded RedDSA type (code 11). Blinding
	// always produces a RedDSA alpha, so this is the sigtype-out value.
	SigTypeRedDSASha512Ed25519 uint16 = 11
)

const (
	// blindingAlphaPrefix is mixed into the salt, matching Java's INFO_ALPHA.
	blindingAlphaPrefix = "I2PGenerateAlpha"
	// blindingInfo is the HKDF info string, matching Java's INFO.
	blindingInfo = "i2pblinding1"
)

// DeriveBlindingFactorI2P derives the I2P destination-blinding factor (alpha)
// exactly as specified by the I2P reference implementation
// (net.i2p.crypto.Blinding.generateAlpha), so the result interoperates with
// Java I2P and other conforming routers.
//
// The derivation is:
//
//	salt = SHA256("I2PGenerateAlpha" || spk || sigtypeIn(2, BE) || 0x000b)
//	ikm  = yyyyMMdd(GMT) || secretUTF8      // secret may be empty
//	out  = HKDF-SHA256(salt, ikm, "i2pblinding1", 64)
//	alpha = reduce(out)                     // 64-byte LE integer mod L, 32-byte LE
//
// Parameters:
//   - signingPubKey: the destination's 32-byte signing public key (spk). It is a
//     mandatory input: the alpha is bound to a specific destination.
//   - secret: optional UTF-8 secret mixed into the IKM (may be empty).
//   - sigType: the destination's signing type code, SigTypeEdDSASha512Ed25519 (7)
//     or SigTypeRedDSASha512Ed25519 (11).
//   - t: the time whose GMT yyyyMMdd value is used as the rotation period.
//
// Returns the 32-byte canonical little-endian alpha scalar.
//
// Spec: I2P Proposal 123 (Encrypted LeaseSet) / net.i2p.crypto.Blinding.
func DeriveBlindingFactorI2P(signingPubKey []byte, secret string, sigType uint16, t time.Time) ([32]byte, error) {
	var alpha [32]byte

	if len(signingPubKey) != 32 {
		return alpha, oops.Errorf("blinding: signing public key must be 32 bytes, got %d", len(signingPubKey))
	}
	if sigType != SigTypeEdDSASha512Ed25519 && sigType != SigTypeRedDSASha512Ed25519 {
		return alpha, oops.Errorf("blinding: unsupported sig type %d (want 7 or 11)", sigType)
	}

	// salt = SHA256("I2PGenerateAlpha" || spk || sigtypeIn(2 BE) || sigtypeOut(2 BE))
	// where sigtypeOut is always RedDSA (11) for a blinded key.
	saltInput := make([]byte, 0, len(blindingAlphaPrefix)+32+2+2)
	saltInput = append(saltInput, blindingAlphaPrefix...)
	saltInput = append(saltInput, signingPubKey...)
	saltInput = appendBE16(saltInput, sigType)
	saltInput = appendBE16(saltInput, SigTypeRedDSASha512Ed25519)
	salt := sha256.Sum256(saltInput)

	// ikm = yyyyMMdd (GMT) || secretUTF8
	mod := t.UTC().Format("20060102")
	ikm := append([]byte(mod), []byte(secret)...)

	// out = HKDF-SHA256(salt, ikm, "i2pblinding1", 64)
	out, err := StandardHKDF(salt[:], ikm, []byte(blindingInfo), 64)
	if err != nil {
		return alpha, oops.Wrapf(err, "blinding: HKDF derivation failed")
	}

	// alpha = out (64-byte little-endian) reduced mod L, encoded as 32-byte LE.
	s, err := (&edwards25519.Scalar{}).SetUniformBytes(out)
	if err != nil {
		return alpha, oops.Wrapf(err, "blinding: failed to reduce to canonical scalar")
	}
	copy(alpha[:], s.Bytes())

	return alpha, nil
}

// appendBE16 appends v as two big-endian bytes.
func appendBE16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
