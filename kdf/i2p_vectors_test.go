package kdf

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-i2p/crypto/hkdf"
)

// LoadI2PVectorTestCases loads test vectors from i2p-vectors/samples/*.json files
func LoadI2PVectorTestCases(vectorType string) ([]map[string]interface{}, error) {
	// Find the i2p-vectors directory relative to the crypto package
	// Starting from the current package location
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// Try common paths where i2p-vectors might be located
	possiblePaths := []string{
		filepath.Join(cwd, "..", "..", "i2p-vectors", "samples", "crypto.json"),
		filepath.Join(cwd, "../../i2p-vectors/samples/crypto.json"),
		"/home/idk/go/src/github.com/go-i2p/i2p-vectors/samples/crypto.json",
	}

	var content []byte
	for _, path := range possiblePaths {
		if data, err := os.ReadFile(path); err == nil {
			content = data
			break
		}
	}

	if content == nil {
		return nil, os.ErrNotExist
	}

	// Parse JSON
	var doc struct {
		Vectors []map[string]interface{} `json:"vectors"`
	}

	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, err
	}

	return doc.Vectors, nil
}

// TestI2PVectorsFromJSON loads and validates test vectors from i2p-vectors JSON files
func TestI2PVectorsFromJSON(t *testing.T) {
	vectors, err := LoadI2PVectorTestCases("crypto")
	if err != nil {
		t.Skipf("Could not load i2p-vectors: %v", err)
	}

	for _, vec := range vectors {
		name, ok := vec["name"].(string)
		if !ok {
			continue
		}

		// Only test HKDF vectors
		if name != "hkdf-derive-32-bytes" {
			continue
		}

		t.Run(name, func(t *testing.T) {
			// Extract inputs
			inputs, ok := vec["inputs"].(map[string]interface{})
			if !ok {
				t.Fatalf("Invalid inputs structure")
			}

			ikmHex, ok := inputs["ikm_hex"].(string)
			if !ok {
				t.Fatalf("Missing ikm_hex")
			}

			saltHex, ok := inputs["salt_hex"].(string)
			if !ok {
				t.Fatalf("Missing salt_hex")
			}

			infoUtf8, ok := inputs["info_utf8"].(string)
			if !ok {
				t.Fatalf("Missing info_utf8")
			}

			// Extract expected output
			expected, ok := vec["expected"].(map[string]interface{})
			if !ok {
				t.Fatalf("Invalid expected structure")
			}

			outputHex, ok := expected["output_hex"].(string)
			if !ok {
				t.Fatalf("Missing output_hex")
			}

			outputLen, ok := expected["output_len"].(float64)
			if !ok {
				t.Fatalf("Missing output_len")
			}

			// Decode inputs
			ikm, err := hex.DecodeString(ikmHex)
			if err != nil {
				t.Fatalf("Failed to decode ikm_hex: %v", err)
			}

			salt, err := hex.DecodeString(saltHex)
			if err != nil {
				t.Fatalf("Failed to decode salt_hex: %v", err)
			}

			expectedOutput, err := hex.DecodeString(outputHex)
			if err != nil {
				t.Fatalf("Failed to decode output_hex: %v", err)
			}

			// Test HKDF derivation
			h := hkdf.NewHKDF()
			output, err := h.Derive(ikm, salt, []byte(infoUtf8), int(outputLen))
			if err != nil {
				t.Fatalf("HKDF Derive failed: %v", err)
			}

			// Compare output
			if hex.EncodeToString(output) != hex.EncodeToString(expectedOutput) {
				t.Errorf("Output mismatch\n"+
					"IKM:      %s\n"+
					"Salt:     %s\n"+
					"Info:     %s\n"+
					"Got:      %s\n"+
					"Expected: %s",
					ikmHex,
					saltHex,
					infoUtf8,
					hex.EncodeToString(output),
					hex.EncodeToString(expectedOutput))
			}
		})
	}
}
