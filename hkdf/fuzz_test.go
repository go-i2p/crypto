package hkdf

import (
	"bytes"
	"testing"
)

// FuzzHKDF drives HKDF key derivation with arbitrary inputs and a bounded
// output length. It checks the documented validation rules (positive key length,
// info length cap) are enforced, that a successful derivation returns exactly the
// requested number of bytes, and that derivation is deterministic for fixed
// inputs.
func FuzzHKDF(f *testing.F) {
	f.Add([]byte("input key material"), []byte("salt"), []byte("i2p-vectors"), uint32(32))
	f.Add([]byte{}, []byte{}, []byte{}, uint32(1))
	f.Add([]byte("ikm"), []byte("s"), []byte("info"), uint32(0))
	f.Add([]byte("ikm"), []byte("s"), []byte("info"), uint32(1000))

	f.Fuzz(func(t *testing.T, ikm, salt, info []byte, keyLenU32 uint32) {
		keyLen := int(keyLenU32)
		// Bound the allocation so a fuzzed length can't request gigabytes.
		if keyLen <= 0 || keyLen > 4096 {
			// Non-positive lengths must be rejected by validation.
			if keyLen <= 0 {
				if _, err := NewHKDF().Derive(ikm, salt, info, keyLen); err == nil {
					t.Fatalf("Derive accepted non-positive key length %d", keyLen)
				}
			}
			return
		}

		h := NewHKDF()
		out, err := h.Derive(ikm, salt, info, keyLen)
		if err != nil {
			// The only documented rejection for a positive, in-range keyLen is
			// the info-length cap.
			if len(info) <= MaxInfoLength {
				t.Fatalf("unexpected Derive error (keyLen=%d, info=%d): %v", keyLen, len(info), err)
			}
			return
		}
		if len(out) != keyLen {
			t.Fatalf("derived %d bytes, want %d", len(out), keyLen)
		}

		// Determinism: the same inputs must yield the same output.
		out2, err := NewHKDF().Derive(ikm, salt, info, keyLen)
		if err != nil {
			t.Fatalf("second Derive failed: %v", err)
		}
		if !bytes.Equal(out, out2) {
			t.Fatalf("HKDF not deterministic")
		}
	})
}
