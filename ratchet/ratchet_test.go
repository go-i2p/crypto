// Package ratchet tests for cryptographic ratcheting mechanisms.
package ratchet

import (
	"bytes"
	"testing"

	"github.com/go-i2p/crypto/rand"
)

// TestTagRatchet tests the session tag ratchet functionality
func TestTagRatchet(t *testing.T) {
	t.Run("BasicTagGeneration", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewTagRatchet(chainKey)

		// Generate 10 tags and ensure they're unique
		tags := make(map[[SessionTagSize]byte]bool)
		for i := 0; i < 10; i++ {
			tag, err := ratchet.GenerateNextTag()
			if err != nil {
				t.Fatalf("failed to generate tag %d: %v", i, err)
			}

			if tags[tag] {
				t.Errorf("duplicate tag generated: %x", tag)
			}
			tags[tag] = true
		}

		if len(tags) != 10 {
			t.Errorf("expected 10 unique tags, got %d", len(tags))
		}
	})

	t.Run("PeekNextTag", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewTagRatchet(chainKey)

		// Peek should return the same tag multiple times
		tag1, err := ratchet.PeekNextTag()
		if err != nil {
			t.Fatalf("failed to peek tag: %v", err)
		}

		tag2, err := ratchet.PeekNextTag()
		if err != nil {
			t.Fatalf("failed to peek tag: %v", err)
		}

		if !bytes.Equal(tag1[:], tag2[:]) {
			t.Errorf("peek returned different tags")
		}

		// Generate should return the peeked tag
		tag3, err := ratchet.GenerateNextTag()
		if err != nil {
			t.Fatalf("failed to generate tag: %v", err)
		}

		if !bytes.Equal(tag1[:], tag3[:]) {
			t.Errorf("generated tag differs from peeked tag")
		}
	})

	t.Run("TagCount", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		ratchet := NewTagRatchet(chainKey)

		if ratchet.GetTagCount() != 0 {
			t.Errorf("initial tag count should be 0, got %d", ratchet.GetTagCount())
		}

		for i := 1; i <= 5; i++ {
			_, err := ratchet.GenerateNextTag()
			if err != nil {
				t.Fatalf("failed to generate tag: %v", err)
			}
			if ratchet.GetTagCount() != uint32(i) {
				t.Errorf("expected tag count %d, got %d", i, ratchet.GetTagCount())
			}
		}
	})

	t.Run("Zero", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewTagRatchet(chainKey)
		ratchet.Zero()

		// Verify chain key is zeroed
		zeroKey := [ChainKeySize]byte{}
		if !bytes.Equal(ratchet.chainKey[:], zeroKey[:]) {
			t.Errorf("chain key not zeroed")
		}
		if ratchet.tagCount != 0 {
			t.Errorf("tag count not zeroed")
		}
	})
}

// TestSymmetricRatchet tests the symmetric key ratchet functionality
func TestSymmetricRatchet(t *testing.T) {
	t.Run("MessageKeyDerivation", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewSymmetricRatchet(chainKey)

		// Derive message keys for different message numbers
		key0, err := ratchet.DeriveMessageKey(0)
		if err != nil {
			t.Fatalf("failed to derive message key 0: %v", err)
		}

		key1, err := ratchet.DeriveMessageKey(1)
		if err != nil {
			t.Fatalf("failed to derive message key 1: %v", err)
		}

		// Keys should be different
		if bytes.Equal(key0[:], key1[:]) {
			t.Errorf("message keys for different numbers should differ")
		}

		// Same message number should give same key (before advance)
		key0Again, err := ratchet.DeriveMessageKey(0)
		if err != nil {
			t.Fatalf("failed to derive message key 0 again: %v", err)
		}

		if !bytes.Equal(key0[:], key0Again[:]) {
			t.Errorf("same message number should give same key")
		}
	})

	t.Run("Advance", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewSymmetricRatchet(chainKey)
		oldChainKey := ratchet.GetChainKey()

		if err := ratchet.Advance(); err != nil {
			t.Fatalf("failed to advance ratchet: %v", err)
		}

		newChainKey := ratchet.GetChainKey()

		if bytes.Equal(oldChainKey[:], newChainKey[:]) {
			t.Errorf("chain key should change after advance")
		}
	})

	t.Run("DeriveMessageKeyAndAdvance", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewSymmetricRatchet(chainKey)
		initialChainKey := ratchet.GetChainKey()

		messageKey, oldChainKey, err := ratchet.DeriveMessageKeyAndAdvance(0)
		if err != nil {
			t.Fatalf("failed to derive and advance: %v", err)
		}

		// Old chain key should match initial
		if !bytes.Equal(oldChainKey[:], initialChainKey[:]) {
			t.Errorf("returned old chain key doesn't match initial")
		}

		// Chain key should have advanced
		newChainKey := ratchet.GetChainKey()
		if bytes.Equal(newChainKey[:], initialChainKey[:]) {
			t.Errorf("chain key should have advanced")
		}

		// Message key should be non-zero
		zeroKey := [MessageKeySize]byte{}
		if bytes.Equal(messageKey[:], zeroKey[:]) {
			t.Errorf("message key should be non-zero")
		}
	})
}

// TestDHRatchet tests the DH ratchet functionality
func TestDHRatchet(t *testing.T) {
	t.Run("PerformRatchet", func(t *testing.T) {
		// Generate two key pairs
		var rootKey, privKey1 [ChainKeySize]byte
		var pubKey2 [PublicKeySize]byte

		if _, err := rand.Read(rootKey[:]); err != nil {
			t.Fatalf("failed to generate root key: %v", err)
		}
		if _, err := rand.Read(privKey1[:]); err != nil {
			t.Fatalf("failed to generate private key 1: %v", err)
		}
		if _, err := rand.Read(pubKey2[:]); err != nil {
			t.Fatalf("failed to generate public key 2: %v", err)
		}

		ratchet := NewDHRatchet(rootKey, privKey1, pubKey2)

		sendKey, recvKey, err := ratchet.PerformRatchet()
		if err != nil {
			t.Fatalf("failed to perform DH ratchet: %v", err)
		}

		// Keys should be different
		if bytes.Equal(sendKey[:], recvKey[:]) {
			t.Errorf("sending and receiving keys should differ")
		}

		// Keys should be non-zero
		zeroKey := [ChainKeySize]byte{}
		if bytes.Equal(sendKey[:], zeroKey[:]) {
			t.Errorf("sending key should be non-zero")
		}
		if bytes.Equal(recvKey[:], zeroKey[:]) {
			t.Errorf("receiving key should be non-zero")
		}
	})

	t.Run("UpdateKeys", func(t *testing.T) {
		var rootKey, privKey, oldPubKey [ChainKeySize]byte
		if _, err := rand.Read(rootKey[:]); err != nil {
			t.Fatalf("failed to generate root key: %v", err)
		}

		ratchet := NewDHRatchet(rootKey, privKey, oldPubKey)

		newPubKey := make([]byte, PublicKeySize)
		if _, err := rand.Read(newPubKey); err != nil {
			t.Fatalf("failed to generate new public key: %v", err)
		}

		if err := ratchet.UpdateKeys(newPubKey); err != nil {
			t.Fatalf("failed to update keys: %v", err)
		}

		if !bytes.Equal(ratchet.theirPubKey[:], newPubKey) {
			t.Errorf("public key not updated correctly")
		}
	})

	t.Run("GenerateNewKeyPair", func(t *testing.T) {
		var rootKey, privKey, pubKey [ChainKeySize]byte
		ratchet := NewDHRatchet(rootKey, privKey, pubKey)

		newPubKey, err := ratchet.GenerateNewKeyPair()
		if err != nil {
			t.Fatalf("failed to generate new key pair: %v", err)
		}

		// New public key should be non-zero
		zeroKey := [PublicKeySize]byte{}
		if bytes.Equal(newPubKey[:], zeroKey[:]) {
			t.Errorf("generated public key should be non-zero")
		}
	})
}

// TestRatchetSymmetricKey tests the utility function
func TestRatchetSymmetricKey(t *testing.T) {
	var chainKey [ChainKeySize]byte
	if _, err := rand.Read(chainKey[:]); err != nil {
		t.Fatalf("failed to generate chain key: %v", err)
	}

	messageKey, newChainKey, err := RatchetSymmetricKey(chainKey, 0)
	if err != nil {
		t.Fatalf("RatchetSymmetricKey failed: %v", err)
	}

	// Keys should be different
	if bytes.Equal(messageKey[:], newChainKey[:]) {
		t.Errorf("message key and new chain key should differ")
	}

	// Keys should differ from original chain key
	if bytes.Equal(messageKey[:], chainKey[:]) {
		t.Errorf("message key should differ from chain key")
	}
	if bytes.Equal(newChainKey[:], chainKey[:]) {
		t.Errorf("new chain key should differ from old chain key")
	}
}

// BenchmarkTagRatchet benchmarks tag generation
func BenchmarkTagRatchet(b *testing.B) {
	var chainKey [ChainKeySize]byte
	rand.Read(chainKey[:])
	ratchet := NewTagRatchet(chainKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ratchet.GenerateNextTag()
	}
}

// BenchmarkSymmetricRatchet benchmarks message key derivation
func BenchmarkSymmetricRatchet(b *testing.B) {
	var chainKey [ChainKeySize]byte
	rand.Read(chainKey[:])
	ratchet := NewSymmetricRatchet(chainKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ratchet.DeriveMessageKey(uint32(i))
	}
}

// BenchmarkDHRatchet benchmarks DH ratchet operations
func BenchmarkDHRatchet(b *testing.B) {
	var rootKey, privKey, pubKey [ChainKeySize]byte
	rand.Read(rootKey[:])
	rand.Read(privKey[:])
	rand.Read(pubKey[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ratchet := NewDHRatchet(rootKey, privKey, pubKey)
		_, _, _ = ratchet.PerformRatchet()
	}
}

// TestZeroValueFootguns demonstrates why direct construction is dangerous
func TestZeroValueFootguns(t *testing.T) {
	t.Run("DHRatchet zero-value is cryptographically invalid", func(t *testing.T) {
		// WRONG: Direct construction with zero values
		var badRatchet DHRatchet

		// This will produce weak/invalid keys because all internal state is zero
		sendKey, recvKey, err := badRatchet.PerformRatchet()
		if err != nil {
			t.Logf("Expected behavior: DH ratchet with zero keys fails: %v", err)
		}

		// Even if it succeeds, the keys will be derived from all-zero state
		zeroKey := [ChainKeySize]byte{}
		if bytes.Equal(sendKey[:], zeroKey[:]) && bytes.Equal(recvKey[:], zeroKey[:]) {
			t.Log("Zero-value DHRatchet produces zero keys - cryptographically invalid!")
		}

		// CORRECT: Always use constructor
		var rootKey, privKey, pubKey [ChainKeySize]byte
		rand.Read(rootKey[:])
		rand.Read(privKey[:])
		rand.Read(pubKey[:])
		goodRatchet := NewDHRatchet(rootKey, privKey, pubKey)

		sendKeyGood, _, err := goodRatchet.PerformRatchet()
		if err != nil {
			t.Fatalf("Constructor-initialized ratchet should work: %v", err)
		}
		if bytes.Equal(sendKeyGood[:], zeroKey[:]) {
			t.Error("Properly initialized ratchet produced zero keys - unexpected!")
		}
	})

	t.Run("SymmetricRatchet zero-value produces predictable keys", func(t *testing.T) {
		// WRONG: Direct construction with zero chain key
		var badRatchet SymmetricRatchet

		// Keys will be derived from all-zero chain key - predictable and weak
		key1, err := badRatchet.DeriveMessageKey(0)
		if err != nil {
			t.Fatalf("DeriveMessageKey failed: %v", err)
		}

		// Create another zero-value ratchet
		var badRatchet2 SymmetricRatchet
		key2, err := badRatchet2.DeriveMessageKey(0)
		if err != nil {
			t.Fatalf("DeriveMessageKey failed: %v", err)
		}

		// They produce identical keys - no randomness!
		if bytes.Equal(key1[:], key2[:]) {
			t.Log("Zero-value SymmetricRatchet produces identical keys - cryptographically invalid!")
		}

		// CORRECT: Always use constructor with random chain key
		var chainKey [ChainKeySize]byte
		rand.Read(chainKey[:])
		goodRatchet := NewSymmetricRatchet(chainKey)

		keyGood, err := goodRatchet.DeriveMessageKey(0)
		if err != nil {
			t.Fatalf("Constructor-initialized ratchet should work: %v", err)
		}

		// Should differ from zero-state keys
		if bytes.Equal(keyGood[:], key1[:]) {
			t.Error("Properly initialized ratchet produced same key as zero-state - unexpected!")
		}
	})

	t.Run("TagRatchet zero-value produces predictable tags", func(t *testing.T) {
		// WRONG: Direct construction with zero chain key
		var badRatchet TagRatchet

		// Tags will be derived from all-zero chain key - predictable
		tag1, err := badRatchet.GenerateNextTag()
		if err != nil {
			t.Fatalf("GenerateNextTag failed: %v", err)
		}

		// Create another zero-value ratchet
		var badRatchet2 TagRatchet
		tag2, err := badRatchet2.GenerateNextTag()
		if err != nil {
			t.Fatalf("GenerateNextTag failed: %v", err)
		}

		// They produce identical tags - no randomness!
		if bytes.Equal(tag1[:], tag2[:]) {
			t.Log("Zero-value TagRatchet produces identical tags - cryptographically invalid!")
		}

		// CORRECT: Always use constructor with random chain key
		var chainKey [ChainKeySize]byte
		rand.Read(chainKey[:])
		goodRatchet := NewTagRatchet(chainKey)

		tagGood, err := goodRatchet.GenerateNextTag()
		if err != nil {
			t.Fatalf("Constructor-initialized ratchet should work: %v", err)
		}

		// Should differ from zero-state tags
		if bytes.Equal(tagGood[:], tag1[:]) {
			t.Error("Properly initialized ratchet produced same tag as zero-state - unexpected!")
		}
	})
}
