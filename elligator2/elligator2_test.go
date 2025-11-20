package elligator2

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// TestEncodeDecodeRoundTrip tests that encode/decode is reversible for suitable keys
func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		runs int
	}{
		{"single round trip", 1},
		{"multiple round trips", 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < tt.runs; i++ {
				// Generate an Elligator2-suitable key pair
				pubKey, _, err := GenerateKeyPair()
				if err != nil {
					t.Fatalf("Run %d: GenerateKeyPair failed: %v", i, err)
				}

				// Encode the public key
				encoded, err := Encode(pubKey)
				if err != nil {
					t.Fatalf("Run %d: Encode failed: %v", i, err)
				}

				// Verify encoded size
				if len(encoded) != RepresentativeSize {
					t.Errorf("Run %d: encoded size = %d, want %d", i, len(encoded), RepresentativeSize)
				}

				// Decode back to public key
				decoded, err := Decode(encoded)
				if err != nil {
					t.Fatalf("Run %d: Decode failed: %v", i, err)
				}

				// Verify the decoded key matches the original
				if !bytes.Equal(decoded, pubKey) {
					t.Errorf("Run %d: decoded key doesn't match original\noriginal: %x\ndecoded:  %x",
						i, pubKey, decoded)
				}
			}
		})
	}
}

// TestInvalidInputs tests error handling for invalid inputs
func TestInvalidInputs(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		input     []byte
		wantErr   bool
	}{
		{
			name:      "encode with nil input",
			operation: "encode",
			input:     nil,
			wantErr:   true,
		},
		{
			name:      "encode with empty input",
			operation: "encode",
			input:     []byte{},
			wantErr:   true,
		},
		{
			name:      "encode with short input",
			operation: "encode",
			input:     make([]byte, 16),
			wantErr:   true,
		},
		{
			name:      "encode with long input",
			operation: "encode",
			input:     make([]byte, 64),
			wantErr:   true,
		},
		{
			name:      "decode with nil input",
			operation: "decode",
			input:     nil,
			wantErr:   true,
		},
		{
			name:      "decode with empty input",
			operation: "decode",
			input:     []byte{},
			wantErr:   true,
		},
		{
			name:      "decode with short input",
			operation: "decode",
			input:     make([]byte, 16),
			wantErr:   true,
		},
		{
			name:      "decode with long input",
			operation: "decode",
			input:     make([]byte, 64),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.operation == "encode" {
				_, err = Encode(tt.input)
			} else {
				_, err = Decode(tt.input)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestGenerateKeyPair tests key pair generation
func TestGenerateKeyPair(t *testing.T) {
	const numTests = 10

	for i := 0; i < numTests; i++ {
		pubKey, privKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Run %d: GenerateKeyPair failed: %v", i, err)
		}

		// Verify key sizes
		if len(pubKey) != PublicKeySize {
			t.Errorf("Run %d: public key size = %d, want %d", i, len(pubKey), PublicKeySize)
		}
		if len(privKey) != PrivateKeySize {
			t.Errorf("Run %d: private key size = %d, want %d", i, len(privKey), PrivateKeySize)
		}

		// Verify public key is Elligator2-representable
		if !IsRepresentable(pubKey) {
			t.Errorf("Run %d: generated public key is not Elligator2-representable", i)
		}

		// Verify we can encode it
		encoded, err := Encode(pubKey)
		if err != nil {
			t.Errorf("Run %d: Encode failed for generated key: %v", i, err)
		}

		// Verify encoded output has entropy
		if isAllZeros(encoded) {
			t.Errorf("Run %d: encoded output is all zeros (not random)", i)
		}
	}
}

// TestIsRepresentable tests the representability check
func TestIsRepresentable(t *testing.T) {
	// Test with valid Elligator2 key
	pubKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if !IsRepresentable(pubKey) {
		t.Error("Generated key should be representable")
	}

	// Test with invalid sizes
	if IsRepresentable(nil) {
		t.Error("nil should not be representable")
	}

	if IsRepresentable(make([]byte, 16)) {
		t.Error("Short key should not be representable")
	}
}

// TestEncodedRandomness tests that encoded values appear random
func TestEncodedRandomness(t *testing.T) {
	const numSamples = 50

	// Collect samples of encoded keys
	samples := make([][]byte, numSamples)
	for i := 0; i < numSamples; i++ {
		pubKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Sample %d: GenerateKeyPair failed: %v", i, err)
		}

		encoded, err := Encode(pubKey)
		if err != nil {
			t.Fatalf("Sample %d: Encode failed: %v", i, err)
		}

		samples[i] = encoded
	}

	// Test 1: No duplicate encodings (collision test)
	seen := make(map[string]bool)
	for i, sample := range samples {
		key := hex.EncodeToString(sample)
		if seen[key] {
			t.Errorf("Sample %d: duplicate encoding found: %s", i, key)
		}
		seen[key] = true
	}

	// Test 2: Each sample should have varying MSB (random bits are working)
	msbVariations := make(map[byte]int)
	for _, sample := range samples {
		msb := sample[31] & 0xC0 // Top 2 bits
		msbVariations[msb]++
	}

	// With 50 samples and 4 possible MSB values (00, 01, 10, 11),
	// we should see multiple different values
	if len(msbVariations) < 2 {
		t.Errorf("MSB randomness insufficient: only %d unique MSB patterns in %d samples",
			len(msbVariations), numSamples)
	}

	// Test 3: Bit distribution check (simple entropy test)
	totalBits := 0
	setBits := 0
	for _, sample := range samples {
		for _, b := range sample {
			for bit := 0; bit < 8; bit++ {
				totalBits++
				if (b>>bit)&1 == 1 {
					setBits++
				}
			}
		}
	}

	// Expect roughly 50% of bits to be set (within reasonable margin)
	expectedSetBits := totalBits / 2
	margin := totalBits / 10 // 10% margin
	if setBits < expectedSetBits-margin || setBits > expectedSetBits+margin {
		t.Logf("Note: Bit distribution is %d set bits out of %d total (expected ~%d)",
			setBits, totalBits, expectedSetBits)
	}
}

// TestMSBMasking tests that MSB bits are properly masked during decode
func TestMSBMasking(t *testing.T) {
	// Generate a valid encoded value
	pubKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	encoded, err := Encode(pubKey)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Decode the original
	decoded1, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Flip the MSB bits (should not affect decoding)
	encodedFlipped := make([]byte, len(encoded))
	copy(encodedFlipped, encoded)
	encodedFlipped[31] ^= 0xC0 // Flip top 2 bits

	// Decode the flipped version
	decoded2, err := Decode(encodedFlipped)
	if err != nil {
		t.Fatalf("Decode failed for flipped MSB: %v", err)
	}

	// Both decodings should produce the same result
	if !bytes.Equal(decoded1, decoded2) {
		t.Error("MSB masking failed: different decoded values")
	}
}

// TestKeyPairUniqueness tests that generated keys are unique
func TestKeyPairUniqueness(t *testing.T) {
	const numKeys = 20

	pubKeys := make(map[string]bool)
	privKeys := make(map[string]bool)

	for i := 0; i < numKeys; i++ {
		pubKey, privKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair failed at iteration %d: %v", i, err)
		}

		pubHex := hex.EncodeToString(pubKey)
		privHex := hex.EncodeToString(privKey)

		if pubKeys[pubHex] {
			t.Errorf("Duplicate public key generated at iteration %d", i)
		}
		if privKeys[privHex] {
			t.Errorf("Duplicate private key generated at iteration %d", i)
		}

		pubKeys[pubHex] = true
		privKeys[privHex] = true
	}

	if len(pubKeys) != numKeys {
		t.Errorf("Expected %d unique public keys, got %d", numKeys, len(pubKeys))
	}
	if len(privKeys) != numKeys {
		t.Errorf("Expected %d unique private keys, got %d", numKeys, len(privKeys))
	}
}

// TestDecodingAlwaysSucceeds tests that any 32-byte input can be decoded
func TestDecodingAlwaysSucceeds(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "all zeros",
			input: make([]byte, 32),
		},
		{
			name:  "all ones",
			input: bytes.Repeat([]byte{0xFF}, 32),
		},
		{
			name:  "alternating bits",
			input: bytes.Repeat([]byte{0xAA}, 32),
		},
		{
			name:  "sequential bytes",
			input: makeSequentialBytes(32),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Decoding should always succeed for valid-sized input
			decoded, err := Decode(tt.input)
			if err != nil {
				t.Errorf("Decode failed for %s: %v", tt.name, err)
			}

			if len(decoded) != PublicKeySize {
				t.Errorf("Decoded size = %d, want %d", len(decoded), PublicKeySize)
			}
		})
	}
}

// TestSuccessRate tests that key generation succeeds reliably
func TestSuccessRate(t *testing.T) {
	const numTrials = 10

	successCount := 0
	for i := 0; i < numTrials; i++ {
		_, _, err := GenerateKeyPair()
		if err == nil {
			successCount++
		}
	}

	// We expect high success rate (should succeed every time with retries)
	if successCount < numTrials {
		t.Errorf("Success rate too low: %d/%d", successCount, numTrials)
	}
}

// TestRandomInputDecode tests decoding random 32-byte values
func TestRandomInputDecode(t *testing.T) {
	for i := 0; i < 10; i++ {
		randomBytes := make([]byte, 32)
		if _, err := rand.Read(randomBytes); err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}

		// Decoding random bytes should always work
		decoded, err := Decode(randomBytes)
		if err != nil {
			t.Errorf("Decode failed for random input %d: %v", i, err)
		}

		if len(decoded) != PublicKeySize {
			t.Errorf("Decoded size = %d, want %d", len(decoded), PublicKeySize)
		}
	}
}

// Helper functions

// isAllZeros checks if a byte slice contains only zeros
func isAllZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// makeSequentialBytes creates a byte slice with sequential values
func makeSequentialBytes(n int) []byte {
	result := make([]byte, n)
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

// Benchmark tests

func BenchmarkEncode(b *testing.B) {
	// Generate a suitable key once
	pubKey, _, err := GenerateKeyPair()
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encode(pubKey)
		if err != nil {
			b.Fatalf("Encode failed: %v", err)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	// Generate and encode a key once
	pubKey, _, err := GenerateKeyPair()
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	encoded, err := Encode(pubKey)
	if err != nil {
		b.Fatalf("Encode failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decode(encoded)
		if err != nil {
			b.Fatalf("Decode failed: %v", err)
		}
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateKeyPair()
		if err != nil {
			b.Fatalf("GenerateKeyPair failed: %v", err)
		}
	}
}

func BenchmarkIsRepresentable(b *testing.B) {
	// Generate a key once
	pubKey, _, err := GenerateKeyPair()
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsRepresentable(pubKey)
	}
}
