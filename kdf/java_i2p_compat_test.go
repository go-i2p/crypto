// Package kdf provides Java I2P compatibility tests
package kdf

import (
	"encoding/hex"
	"testing"

	"github.com/go-i2p/crypto/hkdf"
)

// TestJavaI2PSessionReplyTags validates that our HKDF implementation with
// "SessionReplyTags" info string matches Java I2P 0.9.67 exactly.
//
// Test vectors generated from Java I2P HKDF implementation.
// Source: JAVA_I2P_TEST_VECTORS.yaml
func TestJavaI2PSessionReplyTags(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		data     string
		expected string
	}{
		{
			name:     "SessionReplyTags test 1",
			key:      "7cd84fb3936e7af71b5c14e280483b56c1920669b943fe6aa62563c72af50add",
			data:     "2ae44fc5d10e81363f972b014d12ce4c76e15b899e161dc87242bf32d235c3d6",
			expected: "4c066e39afad9f135b6e1248d18503c6b750aa386dc4388474297a4ff0e17955",
		},
		{
			name:     "SessionReplyTags test 2",
			key:      "2dbdd361df63ef0a02a2d95dec677282fb1c7cef4af6e7b77257b247e56dc40d",
			data:     "5f23c5cfb8b4794254f2f0d3078ac7798377dbeac2143f4206d5568141766c1a",
			expected: "0f881f815c53339d4765a3ff7681ded56b5aaef2a45b4e7c7013c6544fe2d07d",
		},
		{
			name:     "SessionReplyTags test 3",
			key:      "734848aae41ff3341bfd4667ac7cd4546caa3f711118f62ace837166f8fec339",
			data:     "be93ca1bf02a6764a8c35a5e1170c71b571dc81c764ab3a026a400a8c98a886c",
			expected: "ae6c0e33b790cb1114705c332be0d9e9d3cd4ff82e14b2404bd48e7aa4eb4d18",
		},
		{
			name:     "SessionReplyTags test 4",
			key:      "cb28a3ff7005f4441fd3cff44da63683256af852c7971ea91f9c56960bd8e832",
			data:     "24396e94030d050c8ecfc3ba90560509212053f5e9c00218471f77b7cec99f33",
			expected: "33aae500ea0f29a3ec37fc199d238d5b6f5ee445d297a09f16aadfb1362466e8",
		},
		{
			name:     "SessionReplyTags test 5",
			key:      "d44b58c4a008c6dcc7fd90c4cb88c2e48dc2174beef34268cf8b0680bfc37b47",
			data:     "f9cda46cd6e0a98ae978a17ef10ee31a8748e1b5ea9b0a3d62c26376ac123eba",
			expected: "3c024c01326f6b8a68df87cfed1fd491ba744338e8ada42903014f6b899a180a",
		},
		{
			name:     "All zeros - SessionReplyTags",
			key:      "0000000000000000000000000000000000000000000000000000000000000000",
			data:     "0000000000000000000000000000000000000000000000000000000000000000",
			expected: "dd3134e29c9a5219066a29f56248fb13c4d299183bfee3c21abff3ba586f1881",
		},
		{
			name:     "All ones - SessionReplyTags",
			key:      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			data:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expected: "93d7d7f18bb17dd5ad0c18bc900ece1695b88a6679baaf9a5c4476a6edf0b7e4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Decode hex inputs
			key, err := hex.DecodeString(tt.key)
			if err != nil {
				t.Fatalf("Failed to decode key: %v", err)
			}
			data, err := hex.DecodeString(tt.data)
			if err != nil {
				t.Fatalf("Failed to decode data: %v", err)
			}
			expected, err := hex.DecodeString(tt.expected)
			if err != nil {
				t.Fatalf("Failed to decode expected output: %v", err)
			}

			// Java I2P HKDF.calculate(key, data, info, out) uses:
			// - data as IKM (Input Key Material)
			// - key as salt
			// - info string for domain separation
			h := hkdf.NewHKDF()
			output, err := h.Derive(data, key, []byte("SessionReplyTags"), 32)
			if err != nil {
				t.Fatalf("HKDF Derive failed: %v", err)
			}

			// Compare output
			if hex.EncodeToString(output) != hex.EncodeToString(expected) {
				t.Errorf("Output mismatch\nGot:      %s\nExpected: %s",
					hex.EncodeToString(output),
					hex.EncodeToString(expected))
			}
		})
	}
}

// TestJavaI2PAttachPayloadKDF validates that our HKDF implementation with
// "AttachPayloadKDF" info string matches Java I2P 0.9.67 exactly.
//
// Test vectors generated from Java I2P HKDF implementation.
// Source: JAVA_I2P_TEST_VECTORS.yaml
func TestJavaI2PAttachPayloadKDF(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		data     string
		expected string
	}{
		{
			name:     "AttachPayloadKDF test 1",
			key:      "83322b0e178546f67b6ef07c7d93c249c40315369982fd33a908b3ec742846e6",
			data:     "0e543878d260e6d9134739d9cb43c4861a46706b50368b9e0b4ae132800b5b16",
			expected: "046c716daee8ddc330eea8c3368f0657bb209226e6f5a89a4ab86795bf31561f",
		},
		{
			name:     "AttachPayloadKDF test 2",
			key:      "244e4304a25d67db53e8331352af542c0a2fd4f10ae8793df413373a93fd29cd",
			data:     "bc45a8ef5c1ddd479715a6e10d995b4fc7a534f9fcb0f467519da014c538e971",
			expected: "b710aeabc47ccbe819a96ad493d5adf1649fed2c3847ff04dccbad9783de9032",
		},
		{
			name:     "AttachPayloadKDF test 3",
			key:      "ae22f8c19705fac3ca040bd8f9b67aad3427d7f49e05a236be0a64a726148889",
			data:     "c433b90594b82238267e009a96bfa614cbd91e2a0b45a65c41764bb433d8ed4b",
			expected: "1da37c4b21fd62da0a7b31ef17d9d078b7d4d27e52e4e4ab237dbbb16cb09851",
		},
		{
			name:     "AttachPayloadKDF test 4",
			key:      "6d3f8b2ba746de356cd753ec1ef64f5bc3e504dd2cfaff4e70e09ee7b41af6a0",
			data:     "6bf2c75825997622bce01960c487357c87b8f318d91cc71950eed54f84f600be",
			expected: "5ad3862cf9e7ee9ba121668f90d6991cb7b5510bc1eb159b4457bd25e6bd2930",
		},
		{
			name:     "AttachPayloadKDF test 5",
			key:      "1c6e1210c199c510189b5d3638b69567b049536eec4d1e18b0998f0bfc3f34ba",
			data:     "674455928f1899ca75ff663a395eb89fe0e06aeb34d7e196fc07123f017af54e",
			expected: "5e1b2f2a8309eb687a651146cc3da0236c4cd991c294021505261cefa40023e0",
		},
		{
			name:     "All zeros - AttachPayloadKDF",
			key:      "0000000000000000000000000000000000000000000000000000000000000000",
			data:     "0000000000000000000000000000000000000000000000000000000000000000",
			expected: "6be115e80f4962a3e19a738fc651536a9b5a02c95e45fe459bdffac9feb042aa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Decode hex inputs
			key, err := hex.DecodeString(tt.key)
			if err != nil {
				t.Fatalf("Failed to decode key: %v", err)
			}
			data, err := hex.DecodeString(tt.data)
			if err != nil {
				t.Fatalf("Failed to decode data: %v", err)
			}
			expected, err := hex.DecodeString(tt.expected)
			if err != nil {
				t.Fatalf("Failed to decode expected output: %v", err)
			}

			// Java I2P HKDF.calculate(key, data, info, out) uses:
			// - data as IKM (Input Key Material)
			// - key as salt
			// - info string for domain separation
			h := hkdf.NewHKDF()
			output, err := h.Derive(data, key, []byte("AttachPayloadKDF"), 32)
			if err != nil {
				t.Fatalf("HKDF Derive failed: %v", err)
			}

			// Compare output
			if hex.EncodeToString(output) != hex.EncodeToString(expected) {
				t.Errorf("Output mismatch\nGot:      %s\nExpected: %s",
					hex.EncodeToString(output),
					hex.EncodeToString(expected))
			}
		})
	}
}
