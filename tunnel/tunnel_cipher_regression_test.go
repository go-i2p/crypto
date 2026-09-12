package tunnel

import (
	"bytes"
	"testing"
)

// TestAESEncryptRoundTrip verifies encrypt/decrypt produces recoverable payload
// (F079/F080/F081 regression guard — known-answer vector gap flagged in audit).
func TestAESEncryptRoundTrip(t *testing.T) {
	layerKey := TunnelKey{}
	ivKey := TunnelKey{}
	for i := range layerKey {
		layerKey[i] = byte(i)
	}
	for i := range ivKey {
		ivKey[i] = byte(i + 16)
	}

	enc, err := NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("NewAESEncryptor failed: %v", err)
	}

	payload := make([]byte, 1008)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	cipher, err := enc.Encrypt(payload)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(cipher) != 1028 {
		t.Errorf("cipher len=%d, want 1028", len(cipher))
	}

	plain, err := enc.Decrypt(cipher)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if len(plain) != 1008 {
		t.Errorf("plain len=%d, want 1008", len(plain))
	}
	if !bytes.Equal(plain, payload) {
		t.Error("round-trip payload mismatch — cipher mutation lost (F079 regression)")
	}
}
