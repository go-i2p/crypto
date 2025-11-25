package kdf

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"filippo.io/edwards25519"
)

func TestDeriveBlindingFactor(t *testing.T) {
	// Generate a test secret
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		t.Fatalf("Failed to generate test secret: %v", err)
	}

	tests := []struct {
		name    string
		secret  []byte
		date    string
		wantErr bool
	}{
		{
			name:    "valid secret and date",
			secret:  secret,
			date:    "2025-11-24",
			wantErr: false,
		},
		{
			name:    "another valid date",
			secret:  secret,
			date:    "2024-01-01",
			wantErr: false,
		},
		{
			name:    "secret too short",
			secret:  make([]byte, 16),
			date:    "2025-11-24",
			wantErr: true,
		},
		{
			name:    "invalid date format - slashes",
			secret:  secret,
			date:    "11/24/2025",
			wantErr: true,
		},
		{
			name:    "invalid date format - no padding",
			secret:  secret,
			date:    "2025-1-1",
			wantErr: true,
		},
		{
			name:    "invalid date values - Feb 30",
			secret:  secret,
			date:    "2025-02-30",
			wantErr: true,
		},
		{
			name:    "invalid date values - month 13",
			secret:  secret,
			date:    "2025-13-01",
			wantErr: true,
		},
		{
			name:    "leap year Feb 29 valid",
			secret:  secret,
			date:    "2024-02-29",
			wantErr: false,
		},
		{
			name:    "non-leap year Feb 29 invalid",
			secret:  secret,
			date:    "2025-02-29",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alpha, err := DeriveBlindingFactor(tt.secret, tt.date)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify alpha is 32 bytes
			if len(alpha) != 32 {
				t.Errorf("Expected 32-byte alpha, got %d bytes", len(alpha))
			}

			// Verify alpha is not all zeros
			allZero := true
			for _, b := range alpha {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Error("Alpha is all zeros (should be random-looking)")
			}
		})
	}
}

func TestDeriveBlindingFactorDeterminism(t *testing.T) {
	// Generate test secret
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		t.Fatalf("Failed to generate test secret: %v", err)
	}

	date := "2025-11-24"

	// Derive the same blinding factor multiple times
	alpha1, err := DeriveBlindingFactor(secret, date)
	if err != nil {
		t.Fatalf("First derivation failed: %v", err)
	}

	alpha2, err := DeriveBlindingFactor(secret, date)
	if err != nil {
		t.Fatalf("Second derivation failed: %v", err)
	}

	alpha3, err := DeriveBlindingFactor(secret, date)
	if err != nil {
		t.Fatalf("Third derivation failed: %v", err)
	}

	// Verify all three are identical
	if !bytes.Equal(alpha1[:], alpha2[:]) {
		t.Error("alpha1 and alpha2 are different (should be identical)")
	}

	if !bytes.Equal(alpha1[:], alpha3[:]) {
		t.Error("alpha1 and alpha3 are different (should be identical)")
	}

	if !bytes.Equal(alpha2[:], alpha3[:]) {
		t.Error("alpha2 and alpha3 are different (should be identical)")
	}
}

func TestDeriveBlindingFactorDifferentDates(t *testing.T) {
	// Generate test secret
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		t.Fatalf("Failed to generate test secret: %v", err)
	}

	// Derive blinding factors for different dates
	alpha1, err := DeriveBlindingFactor(secret, "2025-11-24")
	if err != nil {
		t.Fatalf("First derivation failed: %v", err)
	}

	alpha2, err := DeriveBlindingFactor(secret, "2025-11-25")
	if err != nil {
		t.Fatalf("Second derivation failed: %v", err)
	}

	alpha3, err := DeriveBlindingFactor(secret, "2024-11-24")
	if err != nil {
		t.Fatalf("Third derivation failed: %v", err)
	}

	// Verify all are different (different dates should produce different alphas)
	if bytes.Equal(alpha1[:], alpha2[:]) {
		t.Error("alpha1 and alpha2 are identical (should be different for different dates)")
	}

	if bytes.Equal(alpha1[:], alpha3[:]) {
		t.Error("alpha1 and alpha3 are identical (should be different for different dates)")
	}

	if bytes.Equal(alpha2[:], alpha3[:]) {
		t.Error("alpha2 and alpha3 are identical (should be different for different dates)")
	}
}

func TestDeriveBlindingFactorDifferentSecrets(t *testing.T) {
	date := "2025-11-24"

	// Generate two different secrets
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)

	_, err := rand.Read(secret1)
	if err != nil {
		t.Fatalf("Failed to generate secret1: %v", err)
	}

	_, err = rand.Read(secret2)
	if err != nil {
		t.Fatalf("Failed to generate secret2: %v", err)
	}

	// Derive blinding factors
	alpha1, err := DeriveBlindingFactor(secret1, date)
	if err != nil {
		t.Fatalf("First derivation failed: %v", err)
	}

	alpha2, err := DeriveBlindingFactor(secret2, date)
	if err != nil {
		t.Fatalf("Second derivation failed: %v", err)
	}

	// Verify they are different
	if bytes.Equal(alpha1[:], alpha2[:]) {
		t.Error("alpha1 and alpha2 are identical (should be different for different secrets)")
	}
}

func TestDeriveBlindingFactorWithTimestamp(t *testing.T) {
	// Generate test secret
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		t.Fatalf("Failed to generate test secret: %v", err)
	}

	// Test with a known timestamp
	// 2025-11-24 00:00:00 UTC
	timestamp := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC).Unix()

	alpha1, err := DeriveBlindingFactorWithTimestamp(secret, timestamp)
	if err != nil {
		t.Fatalf("Timestamp derivation failed: %v", err)
	}

	// Derive the same using the date string
	alpha2, err := DeriveBlindingFactor(secret, "2025-11-24")
	if err != nil {
		t.Fatalf("Date derivation failed: %v", err)
	}

	// Verify they are identical
	if !bytes.Equal(alpha1[:], alpha2[:]) {
		t.Error("Timestamp and date derivations produced different results")
	}

	// Test with a timestamp later in the day (should produce same result)
	timestampLater := time.Date(2025, 11, 24, 23, 59, 59, 0, time.UTC).Unix()
	alpha3, err := DeriveBlindingFactorWithTimestamp(secret, timestampLater)
	if err != nil {
		t.Fatalf("Later timestamp derivation failed: %v", err)
	}

	if !bytes.Equal(alpha1[:], alpha3[:]) {
		t.Error("Different times on same day produced different alphas")
	}
}

func TestFormatDateForBlinding(t *testing.T) {
	tests := []struct {
		name     string
		time     time.Time
		expected string
	}{
		{
			name:     "basic date",
			time:     time.Date(2025, 11, 24, 12, 30, 0, 0, time.UTC),
			expected: "2025-11-24",
		},
		{
			name:     "single digit month and day",
			time:     time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC),
			expected: "2025-01-05",
		},
		{
			name:     "leap year date",
			time:     time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC),
			expected: "2024-02-29",
		},
		{
			name:     "end of year",
			time:     time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
			expected: "2025-12-31",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatDateForBlinding(tt.time)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetCurrentBlindingDate(t *testing.T) {
	date := GetCurrentBlindingDate()

	// Verify format
	if !dateFormatRegex.MatchString(date) {
		t.Errorf("Invalid date format: %q", date)
	}

	// Verify it's a valid date
	_, err := time.Parse("2006-01-02", date)
	if err != nil {
		t.Errorf("Invalid date: %v", err)
	}
}

func TestDeriveBlindingFactorWithEd25519Key(t *testing.T) {
	// Generate a real Ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Use the seed (first 32 bytes of private key) as the secret
	secret := priv.Seed()

	date := "2025-11-24"

	alpha, err := DeriveBlindingFactor(secret, date)
	if err != nil {
		t.Fatalf("Derivation failed: %v", err)
	}

	// Verify alpha is 32 bytes
	if len(alpha) != 32 {
		t.Errorf("Expected 32-byte alpha, got %d bytes", len(alpha))
	}

	// Verify we can derive it again with same result
	alpha2, err := DeriveBlindingFactor(secret, date)
	if err != nil {
		t.Fatalf("Second derivation failed: %v", err)
	}

	if !bytes.Equal(alpha[:], alpha2[:]) {
		t.Error("Derivations with same Ed25519 seed produced different alphas")
	}

	// Just to use the public key (avoid unused variable warning)
	if len(pub) != ed25519.PublicKeySize {
		t.Error("Invalid public key size")
	}
}

// BenchmarkDeriveBlindingFactor benchmarks the blinding factor derivation
func BenchmarkDeriveBlindingFactor(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)
	date := "2025-11-24"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DeriveBlindingFactor(secret, date)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDeriveBlindingFactorWithTimestamp benchmarks timestamp conversion + derivation
func BenchmarkDeriveBlindingFactorWithTimestamp(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)
	timestamp := time.Now().Unix()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DeriveBlindingFactorWithTimestamp(secret, timestamp)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestDeriveBlindingFactorProducesCanonicalScalar verifies that the output
// from DeriveBlindingFactor is a valid canonical Ed25519 scalar that can be
// used with edwards25519.Scalar.SetCanonicalBytes.
// This is the critical test that ensures the bug fix works correctly.
func TestDeriveBlindingFactorProducesCanonicalScalar(t *testing.T) {
	// Generate test secret
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		t.Fatalf("Failed to generate test secret: %v", err)
	}

	// Test with multiple dates to ensure consistency
	dates := []string{
		"2025-11-24",
		"2024-01-01",
		"2025-12-31",
		"2024-02-29", // leap year
	}

	for _, date := range dates {
		t.Run(date, func(t *testing.T) {
			// Derive blinding factor
			alpha, err := DeriveBlindingFactor(secret, date)
			if err != nil {
				t.Fatalf("DeriveBlindingFactor failed: %v", err)
			}

			// CRITICAL TEST: Verify it's a canonical scalar
			// This would fail before the fix (when KDF returned raw 32 bytes)
			alphaScalar, err := (&edwards25519.Scalar{}).SetCanonicalBytes(alpha[:])
			if err != nil {
				t.Fatalf("SetCanonicalBytes failed: %v - alpha is not canonical! This is the bug we're fixing.", err)
			}

			// Verify the scalar is not zero (extremely unlikely but good sanity check)
			zeroScalar := edwards25519.NewScalar()
			if alphaScalar.Equal(zeroScalar) == 1 {
				t.Error("Alpha scalar is zero (should be random)")
			}

			// Verify round-trip: canonical -> bytes -> canonical
			roundTrip, err := (&edwards25519.Scalar{}).SetCanonicalBytes(alphaScalar.Bytes())
			if err != nil {
				t.Fatalf("Round-trip failed: %v", err)
			}

			if roundTrip.Equal(alphaScalar) != 1 {
				t.Error("Round-trip produced different scalar")
			}
		})
	}
}

// TestDeriveBlindingFactorIntegrationWithEd25519Blinding tests the complete
// integration between KDF and Ed25519 blinding as described in the bug report.
// This simulates the actual use case that was failing before the fix.
func TestDeriveBlindingFactorIntegrationWithEd25519Blinding(t *testing.T) {
	// This test requires the ed25519 package's BlindPublicKey function
	// Since we're in the kdf package, we'll verify what we can here:
	// that the alpha is usable as a canonical scalar.

	// Generate Ed25519 keypair
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	secret := priv.Seed()
	date := "2025-11-24"

	// Derive blinding factor using KDF
	alpha, err := DeriveBlindingFactor(secret, date)
	if err != nil {
		t.Fatalf("DeriveBlindingFactor failed: %v", err)
	}

	// Verify it can be parsed as a canonical scalar
	// (This is what ed25519.BlindPublicKey does internally via parseAlphaScalar)
	alphaScalar, err := (&edwards25519.Scalar{}).SetCanonicalBytes(alpha[:])
	if err != nil {
		t.Fatalf("INTEGRATION FAILURE: KDF output cannot be used with BlindPublicKey! Error: %v", err)
	}

	// SUCCESS: If we got here, the KDF output is compatible with BlindPublicKey
	t.Logf("✓ KDF output is a valid canonical scalar for Ed25519 blinding")
	t.Logf("✓ Alpha scalar bytes: %x", alphaScalar.Bytes())
}

// TestDeriveBlindingFactorMultipleDerivations verifies that all derivations
// produce canonical scalars, not just one lucky case.
func TestDeriveBlindingFactorMultipleDerivations(t *testing.T) {
	// Test 100 different secret+date combinations
	for i := 0; i < 100; i++ {
		secret := make([]byte, 32)
		_, err := rand.Read(secret)
		if err != nil {
			t.Fatalf("Failed to generate secret: %v", err)
		}

		// Use varying dates
		date := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, i).Format("2006-01-02")

		alpha, err := DeriveBlindingFactor(secret, date)
		if err != nil {
			t.Fatalf("Derivation %d failed: %v", i, err)
		}

		// Verify it's canonical
		_, err = (&edwards25519.Scalar{}).SetCanonicalBytes(alpha[:])
		if err != nil {
			t.Fatalf("Derivation %d produced non-canonical scalar: %v", i, err)
		}
	}

	t.Logf("✓ All 100 derivations produced valid canonical scalars")
}
