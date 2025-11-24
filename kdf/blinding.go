package kdf

import (
	"regexp"
	"time"

	"github.com/go-i2p/crypto/hkdf"
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
//   - Output: 32 bytes
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
//   - alpha: 32-byte blinding factor suitable for Ed25519 point blinding
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
// Spec: I2P Proposal 123 Section 4.2
func DeriveBlindingFactor(secret []byte, date string) ([32]byte, error) {
	var alpha [32]byte

	// Validate secret length
	if len(secret) < 32 {
		log.WithField("secret_length", len(secret)).
			Error("Secret too short for blinding factor derivation")
		return alpha, oops.Wrapf(ErrInvalidSecret, "got %d bytes, need at least 32", len(secret))
	}

	// Validate date format
	if !dateFormatRegex.MatchString(date) {
		log.WithField("date", date).
			Error("Invalid date format for blinding factor")
		return alpha, oops.Wrapf(ErrInvalidDateFormat, "got %q, expected YYYY-MM-DD", date)
	}

	// Validate date values (check it parses as a valid date)
	if err := validateDate(date); err != nil {
		return alpha, err
	}

	log.WithField("date", date).
		Debug("Deriving blinding factor")

	// Use HKDF to derive blinding factor
	// IKM: secret, Salt: date, Info: "i2p-blinding-factor", Length: 32 bytes
	hkdfDeriver := hkdf.NewHKDF()
	derived, err := hkdfDeriver.Derive(
		secret,
		[]byte(date),
		[]byte("i2p-blinding-factor"),
		32,
	)
	if err != nil {
		return alpha, oops.Wrapf(err, "HKDF derivation failed for blinding factor")
	}

	copy(alpha[:], derived)

	log.WithField("date", date).
		Debug("Blinding factor derived successfully")

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

	log.WithField("timestamp", unixTimestamp).
		WithField("date", date).
		Debug("Converting timestamp to date for blinding factor derivation")

	return DeriveBlindingFactor(secret, date)
}

// validateDate checks if the date string represents a valid calendar date.
// This catches invalid dates like "2025-02-30" or "2025-13-01".
func validateDate(date string) error {
	// Try to parse the date
	_, err := time.Parse("2006-01-02", date)
	if err != nil {
		log.WithField("date", date).
			WithField("error", err).
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
