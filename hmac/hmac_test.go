package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
)

// XXX: IMPLEMENT THIS
func Test_I2PHMAC(t *testing.T) {
	data := make([]byte, 64)
	for idx := range data {
		data[idx] = 1
	}
	var k HMACKey
	for idx := range k[:] {
		k[idx] = 1
	}
	d := I2PHMAC(data, k)

	// Compute expected SHA256-HMAC result
	mac := hmac.New(sha256.New, k[:])
	mac.Write(data)
	expected := mac.Sum(nil)

	if !bytes.Equal(d[:], expected) {
		t.Logf("%d vs %d", len(d), len(expected))
		t.Logf("%x != %x", d, expected)
		t.Fail()
	}
}

// TestNewHMACKey tests the NewHMACKey constructor with various inputs.
func TestNewHMACKey(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		keyData := make([]byte, 32)
		io.ReadFull(rand.Reader, keyData)

		key, err := NewHMACKey(keyData)
		if err != nil {
			t.Errorf("NewHMACKey failed with valid input: %v", err)
		}
		if key == nil {
			t.Error("NewHMACKey returned nil key with valid input")
		}

		// Verify key data matches
		if !bytes.Equal(key[:], keyData) {
			t.Error("NewHMACKey returned key with different data than input")
		}
	})

	t.Run("invalid size - too short", func(t *testing.T) {
		keyData := make([]byte, 16)
		io.ReadFull(rand.Reader, keyData)

		key, err := NewHMACKey(keyData)
		if err == nil {
			t.Error("NewHMACKey should reject 16-byte keys")
		}
		if key != nil {
			t.Error("NewHMACKey should return nil key for invalid size")
		}
	})

	t.Run("invalid size - too long", func(t *testing.T) {
		keyData := make([]byte, 64)
		io.ReadFull(rand.Reader, keyData)

		key, err := NewHMACKey(keyData)
		if err == nil {
			t.Error("NewHMACKey should reject 64-byte keys")
		}
		if key != nil {
			t.Error("NewHMACKey should return nil key for invalid size")
		}
	})

	t.Run("nil input", func(t *testing.T) {
		key, err := NewHMACKey(nil)
		if err == nil {
			t.Error("NewHMACKey should reject nil input")
		}
		if key != nil {
			t.Error("NewHMACKey should return nil key for nil input")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		key, err := NewHMACKey([]byte{})
		if err == nil {
			t.Error("NewHMACKey should reject empty input")
		}
		if key != nil {
			t.Error("NewHMACKey should return nil key for empty input")
		}
	})

	t.Run("all-zero key rejected", func(t *testing.T) {
		keyData := make([]byte, 32) // All zeros

		key, err := NewHMACKey(keyData)
		if err == nil {
			t.Error("NewHMACKey should reject all-zero keys")
		}
		if key != nil {
			t.Error("NewHMACKey should return nil key for all-zero input")
		}
	})

	t.Run("single non-zero byte accepted", func(t *testing.T) {
		keyData := make([]byte, 32)
		keyData[15] = 1 // One non-zero byte

		key, err := NewHMACKey(keyData)
		if err != nil {
			t.Errorf("NewHMACKey should accept key with at least one non-zero byte: %v", err)
		}
		if key == nil {
			t.Error("NewHMACKey returned nil for valid key")
		}
	})
}

// TestGenerateHMACKey tests the random key generation.
func TestGenerateHMACKey(t *testing.T) {
	t.Run("generates valid key", func(t *testing.T) {
		key, err := GenerateHMACKey()
		if err != nil {
			t.Errorf("GenerateHMACKey failed: %v", err)
		}
		if key == nil {
			t.Error("GenerateHMACKey returned nil key")
		}

		// Verify key is not all zeros (extremely unlikely with crypto/rand)
		allZero := true
		for _, b := range key[:] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("GenerateHMACKey generated all-zero key (should be random)")
		}
	})

	t.Run("generates different keys", func(t *testing.T) {
		key1, err := GenerateHMACKey()
		if err != nil {
			t.Fatalf("GenerateHMACKey failed: %v", err)
		}

		key2, err := GenerateHMACKey()
		if err != nil {
			t.Fatalf("GenerateHMACKey failed: %v", err)
		}

		// Keys should be different (collision is astronomically unlikely)
		if bytes.Equal(key1[:], key2[:]) {
			t.Error("GenerateHMACKey generated identical keys (should be random)")
		}
	})

	t.Run("generated keys work with I2PHMAC", func(t *testing.T) {
		key, err := GenerateHMACKey()
		if err != nil {
			t.Fatalf("GenerateHMACKey failed: %v", err)
		}

		data := []byte("test data for HMAC")
		digest := I2PHMAC(data, *key)

		// Verify digest is not all zeros
		allZero := true
		for _, b := range digest[:] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("HMAC digest is all zeros (unexpected)")
		}

		// Verify digest matches expected HMAC-SHA256
		mac := hmac.New(sha256.New, key[:])
		mac.Write(data)
		expected := mac.Sum(nil)

		if !bytes.Equal(digest[:], expected) {
			t.Error("I2PHMAC produced incorrect digest")
		}
	})
}

// TestHMACKeyDefensiveCopy verifies that NewHMACKey creates defensive copies.
func TestHMACKeyDefensiveCopy(t *testing.T) {
	t.Run("modifying source doesn't affect key", func(t *testing.T) {
		keyData := make([]byte, 32)
		io.ReadFull(rand.Reader, keyData)
		original := make([]byte, 32)
		copy(original, keyData)

		key, err := NewHMACKey(keyData)
		if err != nil {
			t.Fatalf("NewHMACKey failed: %v", err)
		}

		// Modify original data
		for i := range keyData {
			keyData[i] = 0xFF
		}

		// Key should still have original data
		if !bytes.Equal(key[:], original) {
			t.Error("NewHMACKey did not create defensive copy - key was modified")
		}
	})
}

// TestHMACKeyZero tests the Zero method for secure memory cleanup.
func TestHMACKeyZero(t *testing.T) {
	t.Run("Zero clears key material", func(t *testing.T) {
		key, err := GenerateHMACKey()
		if err != nil {
			t.Fatalf("GenerateHMACKey failed: %v", err)
		}

		// Verify key is not zero initially
		allZero := true
		for _, b := range key[:] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("Generated key is all zeros (should be random)")
		}

		// Zero the key
		key.Zero()

		// Verify all bytes are zero
		for i, b := range key[:] {
			if b != 0 {
				t.Errorf("Zero() did not clear byte at index %d: got %d, want 0", i, b)
			}
		}
	})

	t.Run("Zero is safe to call multiple times", func(t *testing.T) {
		key, err := GenerateHMACKey()
		if err != nil {
			t.Fatalf("GenerateHMACKey failed: %v", err)
		}

		// Call Zero multiple times
		key.Zero()
		key.Zero()
		key.Zero()

		// Should still be all zeros
		for i, b := range key[:] {
			if b != 0 {
				t.Errorf("Multiple Zero() calls failed: byte at index %d is %d, want 0", i, b)
			}
		}
	})
}

// TestHMACKeyUsagePattern tests the recommended usage pattern with defer.
func TestHMACKeyUsagePattern(t *testing.T) {
	t.Run("defer Zero pattern", func(t *testing.T) {
		// This test demonstrates the recommended pattern
		key, err := GenerateHMACKey()
		if err != nil {
			t.Fatalf("GenerateHMACKey failed: %v", err)
		}
		defer key.Zero()

		// Use the key
		data := []byte("sensitive data")
		digest := I2PHMAC(data, *key)

		// Verify HMAC works
		if len(digest) != 32 {
			t.Errorf("HMAC digest has wrong length: got %d, want 32", len(digest))
		}

		// Key will be zeroed when function returns
	})
}

// TestNew verifies that the New() wrapper produces the same results as crypto/hmac.New.
func TestNew(t *testing.T) {
	t.Run("matches crypto/hmac.New output", func(t *testing.T) {
		key := []byte("test-key-for-hmac-new-function!!")
		data := []byte("hello world")

		// Use our wrapper
		mac := New(sha256.New, key)
		mac.Write(data)
		got := mac.Sum(nil)

		// Use crypto/hmac directly
		stdMac := hmac.New(sha256.New, key)
		stdMac.Write(data)
		want := stdMac.Sum(nil)

		if !bytes.Equal(got, want) {
			t.Errorf("New() digest mismatch:\n  got  %x\n  want %x", got, want)
		}
	})

	t.Run("streaming writes produce correct result", func(t *testing.T) {
		key := []byte("streaming-key-for-hmac-testing!!")
		chunks := [][]byte{
			[]byte("chunk1"),
			[]byte("chunk2"),
			[]byte("chunk3"),
		}

		// Write in chunks via our wrapper
		mac := New(sha256.New, key)
		for _, c := range chunks {
			mac.Write(c)
		}
		got := mac.Sum(nil)

		// Write all at once via crypto/hmac
		stdMac := hmac.New(sha256.New, key)
		for _, c := range chunks {
			stdMac.Write(c)
		}
		want := stdMac.Sum(nil)

		if !bytes.Equal(got, want) {
			t.Errorf("streaming New() digest mismatch:\n  got  %x\n  want %x", got, want)
		}
	})

	t.Run("accepts arbitrary length key", func(t *testing.T) {
		// HMAC spec pads/hashes keys as needed — any length is valid
		shortKey := []byte("k")
		longKey := make([]byte, 128)
		io.ReadFull(rand.Reader, longKey)

		for _, key := range [][]byte{shortKey, longKey} {
			mac := New(sha256.New, key)
			mac.Write([]byte("data"))
			got := mac.Sum(nil)

			stdMac := hmac.New(sha256.New, key)
			stdMac.Write([]byte("data"))
			want := stdMac.Sum(nil)

			if !bytes.Equal(got, want) {
				t.Errorf("New() digest mismatch for key len %d", len(key))
			}
		}
	})

	t.Run("accepts zero-value key for KDF chains", func(t *testing.T) {
		// NTCP2 KDF may start with all-zero key material
		zeroKey := make([]byte, 32)
		mac := New(sha256.New, zeroKey)
		mac.Write([]byte("kdf-input"))
		got := mac.Sum(nil)

		stdMac := hmac.New(sha256.New, zeroKey)
		stdMac.Write([]byte("kdf-input"))
		want := stdMac.Sum(nil)

		if !bytes.Equal(got, want) {
			t.Errorf("New() with zero key mismatch:\n  got  %x\n  want %x", got, want)
		}
	})
}

// TestEqual verifies constant-time MAC comparison.
func TestEqual(t *testing.T) {
	t.Run("equal MACs return true", func(t *testing.T) {
		mac := []byte{0x01, 0x02, 0x03, 0x04}
		if !Equal(mac, mac) {
			t.Error("Equal returned false for identical slices")
		}
		macCopy := make([]byte, len(mac))
		copy(macCopy, mac)
		if !Equal(mac, macCopy) {
			t.Error("Equal returned false for equal slices")
		}
	})

	t.Run("different MACs return false", func(t *testing.T) {
		mac1 := []byte{0x01, 0x02, 0x03, 0x04}
		mac2 := []byte{0x01, 0x02, 0x03, 0x05}
		if Equal(mac1, mac2) {
			t.Error("Equal returned true for different slices")
		}
	})

	t.Run("different lengths return false", func(t *testing.T) {
		mac1 := []byte{0x01, 0x02, 0x03}
		mac2 := []byte{0x01, 0x02, 0x03, 0x04}
		if Equal(mac1, mac2) {
			t.Error("Equal returned true for slices of different length")
		}
	})

	t.Run("empty slices are equal", func(t *testing.T) {
		if !Equal([]byte{}, []byte{}) {
			t.Error("Equal returned false for empty slices")
		}
	})

	t.Run("works with real HMAC digests", func(t *testing.T) {
		key := []byte("test-key-for-equal-verification!")
		data := []byte("important data")

		mac1 := New(sha256.New, key)
		mac1.Write(data)
		digest1 := mac1.Sum(nil)

		mac2 := New(sha256.New, key)
		mac2.Write(data)
		digest2 := mac2.Sum(nil)

		if !Equal(digest1, digest2) {
			t.Error("Equal returned false for matching HMAC digests")
		}

		// Flip a bit
		digest2[0] ^= 0x01
		if Equal(digest1, digest2) {
			t.Error("Equal returned true for tampered HMAC digest")
		}
	})
}

// BenchmarkNewHMACKey benchmarks the constructor performance.
func BenchmarkNewHMACKey(b *testing.B) {
	keyData := make([]byte, 32)
	io.ReadFull(rand.Reader, keyData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewHMACKey(keyData)
	}
}

// BenchmarkGenerateHMACKey benchmarks random key generation.
func BenchmarkGenerateHMACKey(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateHMACKey()
	}
}

// BenchmarkHMACKeyZero benchmarks the Zero method.
func BenchmarkHMACKeyZero(b *testing.B) {
	key, _ := GenerateHMACKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key.Zero()
	}
}
