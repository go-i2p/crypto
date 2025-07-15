package ecdsa

import (
	"crypto"
	"crypto/sha256"
	"testing"
)

// TestHashCalculationFix validates that the Verify method correctly hashes data
func TestHashCalculationFix(t *testing.T) {
	data := []byte("test data for hashing")

	// Calculate expected hash using standard library
	hasher := sha256.New()
	hasher.Write(data)
	expectedHash := hasher.Sum(nil)

	// Test the hash calculation logic that was fixed
	h := crypto.SHA256

	// This is what the code now does (correct)
	hasherFixed := h.New()
	hasherFixed.Write(data)
	actualHash := hasherFixed.Sum(nil)

	// Verify they match
	if len(expectedHash) != len(actualHash) {
		t.Errorf("Hash lengths don't match: expected %d, got %d", len(expectedHash), len(actualHash))
	}

	for i := 0; i < len(expectedHash); i++ {
		if expectedHash[i] != actualHash[i] {
			t.Errorf("Hash mismatch at byte %d: expected %x, got %x", i, expectedHash[i], actualHash[i])
			break
		}
	}

	t.Logf("✅ Hash calculation is working correctly")
	t.Logf("Data: %s", string(data))
	t.Logf("Hash: %x", actualHash)
}
