package kdf

import (
	"bytes"
	"testing"
)

func TestDeriveForPurpose(t *testing.T) {
	rootKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}

	kd := NewKeyDerivation(rootKey)

	purposes := []KeyPurpose{
		PurposeTunnelEncryption,
		PurposeGarlicEncryption,
		PurposeSessionTag,
	}

	keys := make(map[KeyPurpose][32]byte)

	for _, purpose := range purposes {
		key, err := kd.DeriveForPurpose(purpose)
		if err != nil {
			t.Fatalf("DeriveForPurpose failed: %v", err)
		}
		keys[purpose] = key
	}

	// Verify all keys are different
	allPairs := [][2]KeyPurpose{
		{PurposeTunnelEncryption, PurposeGarlicEncryption},
		{PurposeTunnelEncryption, PurposeSessionTag},
		{PurposeGarlicEncryption, PurposeSessionTag},
	}

	for _, pair := range allPairs {
		k1 := keys[pair[0]]
		k2 := keys[pair[1]]
		if bytes.Equal(k1[:], k2[:]) {
			t.Errorf("Keys for %v and %v are identical", pair[0], pair[1])
		}
	}
}

func TestDeriveSessionKeys(t *testing.T) {
	rootKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}

	kd := NewKeyDerivation(rootKey)

	rootKey1, symKey1, tagKey1, err := kd.DeriveSessionKeys()
	if err != nil {
		t.Fatalf("DeriveSessionKeys failed: %v", err)
	}

	// Verify all three keys are different
	if bytes.Equal(rootKey1[:], symKey1[:]) {
		t.Error("Root key and sym key are identical")
	}
	if bytes.Equal(rootKey1[:], tagKey1[:]) {
		t.Error("Root key and tag key are identical")
	}
	if bytes.Equal(symKey1[:], tagKey1[:]) {
		t.Error("Sym key and tag key are identical")
	}
}
