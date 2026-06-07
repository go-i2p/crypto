package hkdf

import (
	"encoding/hex"
	"testing"
)

// TestI2PVectors validates that our HKDF implementation matches the i2p-vectors
// reference vectors that use Java I2P as the ground truth.
func TestI2PVectors(t *testing.T) {
	tests := []struct {
		name        string
		ikmHex      string
		saltHex     string
		info        string
		outputLen   int
		expectedHex string
		description string
	}{
		{
			name:        "hkdf-derive-32-bytes deterministic",
			ikmHex:      "0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a",
			saltHex:     "f0e0d0c0b0a090807060504030201000",
			info:        "i2p-vectors",
			outputLen:   32,
			expectedHex: "47befb26c7cce127bf99f6e18bd35f6328d407c2835f122e7dec23d26f0f8c48",
			description: "Deterministic test vector from i2p-vectors",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Decode hex inputs
			ikm, err := hex.DecodeString(tt.ikmHex)
			if err != nil {
				t.Fatalf("Failed to decode IKM: %v", err)
			}

			salt, err := hex.DecodeString(tt.saltHex)
			if err != nil {
				t.Fatalf("Failed to decode salt: %v", err)
			}

			expected, err := hex.DecodeString(tt.expectedHex)
			if err != nil {
				t.Fatalf("Failed to decode expected: %v", err)
			}

			// Derive using the same calling convention as i2p-vectors
			h := NewHKDF()
			output, err := h.Derive(ikm, salt, []byte(tt.info), tt.outputLen)
			if err != nil {
				t.Fatalf("HKDF Derive failed: %v", err)
			}

			// Compare output
			gotHex := hex.EncodeToString(output)
			expectedStr := hex.EncodeToString(expected)

			if gotHex != expectedStr {
				t.Errorf("Output mismatch (%s)\nDescription: %s\nGot:      %s\nExpected: %s",
					tt.name,
					tt.description,
					gotHex,
					expectedStr)
			} else {
				t.Logf("✓ %s: Output matches expected value", tt.name)
			}
		})
	}
}
