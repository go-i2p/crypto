package kdf

import (
	"crypto/sha256"
	"regexp"
	"time"

	"filippo.io/edwards25519"

	"github.com/go-i2p/crypto/hkdf"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var (
	// ErrInvalidSecret indicates the secret is too short for secure blinding factor derivation
	ErrInvalidSecret = oops.Errorf("secret must be at least 32 bytes")

	// ErrInvalidDateFormat indicates the date string does not match YYYY-MM-DD format
	ErrInvalidDateFormat = oops.Errorf("date must be in YYYY-MM-DD format")

	// ErrInvalidDate indicates the date values are invalid (e.g., Feb 30)
	ErrInvalidDate = oops.Errorf("invalid date values")
)

// Regular expression for YYYY-MM-DD date format validation
var dateFormatRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// DeriveBlindingFactor derives a blinding factor (alpha) from a secret and date.
// This creates a unique per-day blinding factor for EncryptedLeaseSet rotation.
//
// Derivation uses HKDF-SHA256:
//   - IKM (input key material): secret (32+ bytes, typically from destination keypair)
//   - Salt: date in YYYY-MM-DD format as bytes
//   - Info: "i2p-blinding-factor"
//   - Output: 64 bytes (reduced to canonical Ed25519 scalar)
//
// The output is a canonical Ed25519 scalar (reduced modulo L), ensuring compatibility
// with edwards25519.Scalar.SetCanonicalBytes. The derivation process:
//  1. HKDF derives 64 bytes from secret + date
//  2. SetUniformBytes reduces to canonical scalar (< L)
//  3. Returns 32-byte canonical scalar encoding
//
// The same secret + date always produces the same alpha, enabling:
//   - Service to create blinded destination for publication
//   - Clients to derive the same alpha and verify blinded signatures
//
// Parameters:
//   - secret: Secret key material (must be at least 32 bytes, typically from private key)
//   - date: Date in "YYYY-MM-DD" format (e.g., "2025-11-24")
//
// Returns:
//   - alpha: 32-byte canonical Ed25519 scalar suitable for point blinding
//   - error: ErrInvalidSecret if secret is too short, ErrInvalidDateFormat or ErrInvalidDate if date is invalid
//
// Example:
//
//	// Derive blinding factor for today
//	secret := privateKey.Seed() // 32-byte secret from Ed25519 private key
//	alpha, err := kdf.DeriveBlindingFactor(secret, "2025-11-24")
//	if err != nil {
//	    return err
//	}
//
//	// Use alpha to blind public key
//	blindedPubKey, err := ed25519.BlindPublicKey(pubKey, alpha)
//
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

// Spec: I2P Proposal 123 Section 4.2
//
// Deprecated: this is NOT the I2P destination-blinding KDF. It omits the
// destination signing public key and the sig-type codes from the salt, uses the
// date as the HKDF salt rather than the SHA256("I2PGenerateAlpha"||spk||...)
// salt, mixes the secret in as IKM with a YYYY-MM-DD (not yyyyMMdd) prefix, and
// uses info "i2p-blinding-factor" rather than "i2pblinding1". The result is
// self-consistent but interoperates with no I2P implementation. Use
// DeriveBlindingFactorI2P for a conformant alpha.
func DeriveBlindingFactor(secret []byte, date string) ([32]byte, error) {
	var alpha [32]byte

	if err := validateSecretLength(secret); err != nil {
		return alpha, err
	}

	if err := validateDateFormatAndValues(date); err != nil {
		return alpha, err
	}

	log.WithFields(logger.Fields{"pkg": "kdf", "func": "DeriveBlindingFactor", "date": date}).
		Debug("Deriving blinding factor")

	alpha, err := deriveAlphaUsingHKDF(secret, date)
	if err != nil {
		return alpha, err
	}

	log.WithFields(logger.Fields{"pkg": "kdf", "func": "DeriveBlindingFactor", "date": date}).
		Debug("Blinding factor derived successfully")

	return alpha, nil
}

// validateSecretLength checks if the secret meets the minimum length requirement.
func validateSecretLength(secret []byte) error {
	if len(secret) < 32 {
		log.WithFields(logger.Fields{"pkg": "kdf", "func": "validateSecretLength", "secret_length": len(secret)}).
			Error("Secret too short for blinding factor derivation")
		return oops.Wrapf(ErrInvalidSecret, "got %d bytes, need at least 32", len(secret))
	}
	return nil
}

// validateDateFormatAndValues validates both the format and logical validity of a date string.
func validateDateFormatAndValues(date string) error {
	if !dateFormatRegex.MatchString(date) {
		log.WithFields(logger.Fields{"pkg": "kdf", "func": "validateDateFormatAndValues", "date": date}).
			Error("Invalid date format for blinding factor")
		return oops.Wrapf(ErrInvalidDateFormat, "got %q, expected YYYY-MM-DD", date)
	}

	if err := validateDate(date); err != nil {
		return err
	}

	return nil
}

// deriveAlphaUsingHKDF performs HKDF-based derivation to create the blinding factor.
// It derives 64 bytes and reduces them to a canonical Ed25519 scalar to ensure
// compatibility with edwards25519.Scalar.SetCanonicalBytes.
func deriveAlphaUsingHKDF(secret []byte, date string) ([32]byte, error) {
	var alpha [32]byte

	// Use HKDF to derive 64 bytes for uniform scalar reduction
	// IKM: secret, Salt: date, Info: "i2p-blinding-factor", Length: 64 bytes
	hkdfDeriver := hkdf.NewHKDF()
	derived, err := hkdfDeriver.Derive(
		secret,
		[]byte(date),
		[]byte("i2p-blinding-factor"),
		64, // Changed from 32 to 64 for SetUniformBytes
	)
	if err != nil {
		return alpha, oops.Wrapf(err, "HKDF derivation failed for blinding factor")
	}

	// Reduce to canonical scalar using SetUniformBytes
	// This ensures the output is a valid Ed25519 scalar (< L, the group order)
	alphaScalar, err := (&edwards25519.Scalar{}).SetUniformBytes(derived)
	if err != nil {
		return alpha, oops.Wrapf(err, "failed to reduce blinding factor to canonical scalar")
	}

	copy(alpha[:], alphaScalar.Bytes())
	return alpha, nil
}

// DeriveBlindingFactorWithTimestamp is a convenience wrapper that formats
// a Unix timestamp into YYYY-MM-DD and calls DeriveBlindingFactor.
//
// This is useful when working with Unix timestamps (e.g., from time.Now().Unix()).
//
// Parameters:
//   - secret: Secret key material (must be at least 32 bytes)
//   - unixTimestamp: Unix timestamp in seconds
//
// Returns:
//   - alpha: 32-byte blinding factor
//   - error: Same errors as DeriveBlindingFactor
//
// Example:
//
//	// Derive blinding factor for current time
//	now := time.Now().Unix()
//	alpha, err := kdf.DeriveBlindingFactorWithTimestamp(secret, now)
func DeriveBlindingFactorWithTimestamp(secret []byte, unixTimestamp int64) ([32]byte, error) {
	// Convert Unix timestamp to time.Time
	t := time.Unix(unixTimestamp, 0).UTC()

	// Format as YYYY-MM-DD
	date := t.Format("2006-01-02")

	log.WithFields(logger.Fields{"pkg": "kdf", "func": "DeriveBlindingFactorWithTimestamp", "timestamp": unixTimestamp, "date": date}).
		Debug("Converting timestamp to date for blinding factor derivation")

	return DeriveBlindingFactor(secret, date)
}

// validateDate checks if the date string represents a valid calendar date.
// This catches invalid dates like "2025-02-30" or "2025-13-01".
func validateDate(date string) error {
	// Try to parse the date
	_, err := time.Parse("2006-01-02", date)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "kdf", "func": "validateDate", "date": date, "error": err}).
			Error("Invalid date values")
		return oops.Wrapf(ErrInvalidDate, "failed to parse %q: %v", date, err)
	}
	return nil
}

// FormatDateForBlinding formats a time.Time as YYYY-MM-DD for blinding factor derivation.
// This is a convenience function for consistent date formatting.
//
// Example:
//
//	date := kdf.FormatDateForBlinding(time.Now())
//	alpha, err := kdf.DeriveBlindingFactor(secret, date)
func FormatDateForBlinding(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// GetCurrentBlindingDate returns today's date in UTC formatted for blinding.
// This is equivalent to FormatDateForBlinding(time.Now().UTC()).
//
// Example:
//
//	today := kdf.GetCurrentBlindingDate()
//	alpha, err := kdf.DeriveBlindingFactor(secret, today)
func GetCurrentBlindingDate() string {
	return FormatDateForBlinding(time.Now().UTC())
}
