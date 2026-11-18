package argon2

import (
	"math"
	"math/bits"
	"testing"
)

// TestDeriveKeyLengthBounds covers the uint32-truncation regression: keyLen is an
// int that is narrowed to uint32 for argon2.IDKey, so values that do not survive
// that conversion must be rejected rather than silently truncated to a wrong
// (often zero) length.
func TestDeriveKeyLengthBounds(t *testing.T) {
	a := NewArgon2id(1, 8*1024, 1)
	ikm := []byte("input key material")
	salt := []byte("0123456789abcdef")

	// Runtime-computed so the literals don't overflow int at compile time on
	// 32-bit platforms. The overflow cases are only meaningful when int is 64-bit.
	one := 1
	maxPlusOne := math.MaxUint32 + one // wraps to 0 when narrowed to uint32
	shift32 := one << 32               // wraps to 0 when narrowed to uint32
	shift32Plus100 := (one << 32) + 100

	overflowCases := []struct {
		name   string
		keyLen int
	}{
		{"MaxUint32+1", maxPlusOne},
		{"1<<32", shift32},
		{"1<<32+100", shift32Plus100},
	}

	for _, tc := range overflowCases {
		t.Run("overflow/"+tc.name, func(t *testing.T) {
			if bits.UintSize < 64 {
				t.Skip("keyLen overflow cases require a 64-bit int")
			}
			got, err := a.Derive(ikm, salt, nil, tc.keyLen)
			if err != ErrInvalidKeyLength {
				t.Fatalf("keyLen=%d: got err=%v, want ErrInvalidKeyLength", tc.keyLen, err)
			}
			if got != nil {
				t.Fatalf("keyLen=%d: got non-nil key %q on error", tc.keyLen, got)
			}
		})
	}

	// Non-overflow invalid lengths are valid on every platform.
	for _, tc := range []struct {
		name   string
		keyLen int
	}{
		{"zero", 0},
		{"negative", -1},
	} {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			if _, err := a.Derive(ikm, salt, nil, tc.keyLen); err != ErrInvalidKeyLength {
				t.Fatalf("keyLen=%d: got err=%v, want ErrInvalidKeyLength", tc.keyLen, err)
			}
		})
	}
}

// TestDeriveReturnsRequestedLength is the happy-path guard: a valid keyLen must
// produce a key of exactly that length (the truncation bug would otherwise return
// a shorter key without erroring).
func TestDeriveReturnsRequestedLength(t *testing.T) {
	a := NewArgon2id(1, 8*1024, 1)
	ikm := []byte("input key material")
	salt := []byte("0123456789abcdef")

	key, err := a.Derive(ikm, salt, nil, 32)
	if err != nil {
		t.Fatalf("Derive returned unexpected error: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(key))
	}
}
