package kdf

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-i2p/crypto/hkdf"
)

// cryptoVectors is a pinned snapshot of i2p-vectors/samples/crypto.json, the
// authoritative Java-I2P-derived test vectors. Embedding it means the compliance
// suite always has ground truth available and can never silently SKIP just
// because the sibling i2p-vectors checkout happens to be absent (the failure
// mode CR-009 tracks). When the live sibling repo IS present, the loader still
// prefers it so freshly regenerated vectors flow through; the embedded copy is
// the always-available fallback.
//
// To refresh the snapshot after updating i2p-vectors:
//
//	cp ../i2p-vectors/samples/crypto.json kdf/testdata/crypto.json
//
//go:embed testdata/crypto.json
var cryptoVectors []byte

// LoadI2PVectorTestCases loads test vectors from i2p-vectors/samples/crypto.json.
//
// It prefers the live sibling checkout (so freshly regenerated vectors are used
// when present) and falls back to the embedded snapshot, which is always
// available. It therefore never returns os.ErrNotExist purely because the
// sibling repo is missing.
func LoadI2PVectorTestCases(vectorType string) ([]map[string]interface{}, error) {
	var content []byte

	// Prefer the live sibling checkout when present.
	if cwd, err := os.Getwd(); err == nil {
		possiblePaths := []string{
			filepath.Join(cwd, "..", "..", "i2p-vectors", "samples", "crypto.json"),
			"/home/idk/go/src/github.com/go-i2p/i2p-vectors/samples/crypto.json",
		}
		for _, path := range possiblePaths {
			if data, err := os.ReadFile(path); err == nil {
				content = data
				break
			}
		}
	}

	// Fall back to the embedded snapshot so the suite never silently skips.
	if content == nil {
		content = cryptoVectors
	}

	var doc struct {
		Vectors []map[string]interface{} `json:"vectors"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, err
	}
	if len(doc.Vectors) == 0 {
		return nil, os.ErrNotExist
	}
	return doc.Vectors, nil
}

// TestI2PVectorsFromJSON loads and validates test vectors from i2p-vectors JSON
// files. It runs unconditionally: the embedded snapshot guarantees ground truth
// even when the sibling i2p-vectors checkout is absent, so a missing repo no
// longer turns this into a silent SKIP.
func TestI2PVectorsFromJSON(t *testing.T) {
	vectors, err := LoadI2PVectorTestCases("crypto")
	if err != nil {
		// With the embedded snapshot this only happens if the snapshot itself is
		// corrupt or empty, which is a real failure, not a skip.
		t.Fatalf("Could not load i2p-vectors: %v", err)
	}

	const targetVector = "hkdf-derive-32-bytes"
	matched := 0

	for _, vec := range vectors {
		name, ok := vec["name"].(string)
		if !ok {
			continue
		}

		// Only test HKDF vectors here; other algorithms are covered by their own
		// packages' compliance tests.
		if name != targetVector {
			continue
		}
		matched++

		t.Run(name, func(t *testing.T) {
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

			h := hkdf.NewHKDF()
			output, err := h.Derive(ikm, salt, []byte(infoUtf8), int(outputLen))
			if err != nil {
				t.Fatalf("HKDF Derive failed: %v", err)
			}

			if hex.EncodeToString(output) != hex.EncodeToString(expectedOutput) {
				t.Errorf("Output mismatch\n"+
					"IKM:      %s\n"+
					"Salt:     %s\n"+
					"Info:     %s\n"+
					"Got:      %s\n"+
					"Expected: %s",
					ikmHex, saltHex, infoUtf8,
					hex.EncodeToString(output), hex.EncodeToString(expectedOutput))
			}
		})
	}

	// Guard against the vacuous-pass failure mode: if the expected vector is
	// absent from the loaded set, the loop above runs zero subtests and the test
	// would otherwise pass without asserting anything.
	if matched == 0 {
		t.Fatalf("expected vector %q not found in loaded i2p-vectors (loaded %d vectors)", targetVector, len(vectors))
	}
}

// TestEmbeddedVectorsFallback proves the CR-009 fix directly: it validates the
// embedded snapshot WITHOUT consulting the live sibling checkout, so it asserts
// the compliance suite has usable ground truth even when i2p-vectors is absent
// (the CI condition that previously made the suite silently SKIP). If this test
// ever fails, the embedded snapshot is stale or corrupt and the fallback is no
// longer trustworthy.
func TestEmbeddedVectorsFallback(t *testing.T) {
	var doc struct {
		Vectors []map[string]interface{} `json:"vectors"`
	}
	if err := json.Unmarshal(cryptoVectors, &doc); err != nil {
		t.Fatalf("embedded crypto.json snapshot is corrupt: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("embedded crypto.json snapshot contains no vectors")
	}

	const targetVector = "hkdf-derive-32-bytes"
	var vec map[string]interface{}
	for _, v := range doc.Vectors {
		if name, _ := v["name"].(string); name == targetVector {
			vec = v
			break
		}
	}
	if vec == nil {
		t.Fatalf("embedded snapshot is missing the %q vector", targetVector)
	}

	inputs, ok := vec["inputs"].(map[string]interface{})
	if !ok {
		t.Fatalf("embedded %q vector has invalid inputs", targetVector)
	}
	expected, ok := vec["expected"].(map[string]interface{})
	if !ok {
		t.Fatalf("embedded %q vector has invalid expected", targetVector)
	}

	ikm, err := hex.DecodeString(inputs["ikm_hex"].(string))
	if err != nil {
		t.Fatalf("decode ikm_hex: %v", err)
	}
	salt, err := hex.DecodeString(inputs["salt_hex"].(string))
	if err != nil {
		t.Fatalf("decode salt_hex: %v", err)
	}
	info, ok := inputs["info_utf8"].(string)
	if !ok {
		t.Fatal("missing info_utf8")
	}
	outputHex, ok := expected["output_hex"].(string)
	if !ok {
		t.Fatal("missing output_hex")
	}
	outputLen, ok := expected["output_len"].(float64)
	if !ok {
		t.Fatal("missing output_len")
	}
	expectedOutput, err := hex.DecodeString(outputHex)
	if err != nil {
		t.Fatalf("decode output_hex: %v", err)
	}

	h := hkdf.NewHKDF()
	output, err := h.Derive(ikm, salt, []byte(info), int(outputLen))
	if err != nil {
		t.Fatalf("HKDF Derive failed: %v", err)
	}
	if hex.EncodeToString(output) != hex.EncodeToString(expectedOutput) {
		t.Errorf("embedded fallback output mismatch\nGot:      %s\nExpected: %s",
			hex.EncodeToString(output), hex.EncodeToString(expectedOutput))
	}
}
