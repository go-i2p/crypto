package siphash

import (
	"encoding/binary"
	"testing"
)

// golden vectors are SipHash-2-4 outputs taken from the reference test suite
// shipped with github.com/dchest/siphash (public domain). They pin the wrapper's
// behaviour to the upstream implementation so a future swap of the backend can't
// silently change digests.
var golden = []struct {
	name string
	key  []byte // 16 bytes
	data []byte
	want uint64
}{
	{
		name: "sequential key and data",
		key:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		data: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
		want: 0xa129ca6149be45e5,
	},
	{
		name: "hello world",
		key:  make([]byte, 16),
		data: []byte("Hello world"),
		want: 0xc9e8a3021f3822d9,
	},
	{
		name: "zero-length message",
		key:  make([]byte, 16),
		data: []byte{},
		want: 0x1e924b9d737700d7,
	},
	{
		name: "12345678123",
		key:  make([]byte, 16),
		data: []byte("12345678123"),
		want: 0x0f95d77ccdb0649f,
	},
	{
		name: "8 zero bytes",
		key:  make([]byte, 16),
		data: make([]byte, 8),
		want: 0xe849e8bb6ffe2567,
	},
	{
		name: "1535 zero bytes",
		key:  make([]byte, 16),
		data: make([]byte, 1535),
		want: 0xe74d1c0ab64b2afa,
	},
}

func keyParts(key []byte) (uint64, uint64) {
	return binary.LittleEndian.Uint64(key[0:8]), binary.LittleEndian.Uint64(key[8:16])
}

// TestHashKnownVectors checks Hash against reference digests.
func TestHashKnownVectors(t *testing.T) {
	for _, tc := range golden {
		t.Run(tc.name, func(t *testing.T) {
			k0, k1 := keyParts(tc.key)
			if got := Hash(k0, k1, tc.data); got != tc.want {
				t.Errorf("Hash = %016x, want %016x", got, tc.want)
			}
		})
	}
}

// TestStreamingMatchesHash verifies the streaming hash.Hash64 from New produces
// the same digest as the one-shot Hash, including when data is written in
// multiple chunks (the incremental path NTCP2 callers rely on).
func TestStreamingMatchesHash(t *testing.T) {
	for _, tc := range golden {
		t.Run(tc.name, func(t *testing.T) {
			k0, k1 := keyParts(tc.key)
			h := New(tc.key)
			// Write in two chunks to exercise the incremental buffer path.
			mid := len(tc.data) / 2
			if _, err := h.Write(tc.data[:mid]); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if _, err := h.Write(tc.data[mid:]); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if got := h.Sum64(); got != tc.want {
				t.Errorf("streaming Sum64 = %016x, want %016x", got, tc.want)
			}
			// Cross-check against the one-shot form.
			if oneShot := Hash(k0, k1, tc.data); oneShot != h.Sum64() {
				t.Errorf("one-shot %016x != streaming %016x", oneShot, h.Sum64())
			}
		})
	}
}

// TestNew128MatchesHash128 verifies the streaming hash.Hash from New128 matches
// the one-shot Hash128 (both halves), exercising the 128-bit output path.
func TestNew128MatchesHash128(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	k0, k1 := keyParts(key)

	data := []byte("SipHash-2-4-128 streaming equivalence probe")

	lo, hi := Hash128(k0, k1, data)

	h := New128(key)
	if _, err := h.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	sum := h.Sum(nil)
	if len(sum) != 16 {
		t.Fatalf("New128 Sum length = %d, want 16", len(sum))
	}
	streamLo := binary.LittleEndian.Uint64(sum[0:8])
	streamHi := binary.LittleEndian.Uint64(sum[8:16])
	if streamLo != lo || streamHi != hi {
		t.Errorf("New128 streaming (%016x,%016x) != Hash128 (%016x,%016x)", streamLo, streamHi, lo, hi)
	}
}

// TestHash128DistinctHalves sanity-checks that Hash128 returns two independent
// 64-bit halves (they should differ for non-trivial input).
func TestHash128DistinctHalves(t *testing.T) {
	key := make([]byte, 16)
	k0, k1 := keyParts(key)
	lo, hi := Hash128(k0, k1, []byte("distinct halves probe"))
	if lo == hi {
		t.Errorf("Hash128 halves unexpectedly equal: %016x", lo)
	}
}

// TestResetReusesInstance verifies a reused streaming instance produces the same
// digest after Reset, matching the hash.Hash contract.
func TestResetReusesInstance(t *testing.T) {
	key := make([]byte, 16)
	data := []byte("reset reuse check")

	h := New(key)
	h.Write(data)
	first := h.Sum64()

	h.Reset()
	h.Write(data)
	second := h.Sum64()

	if first != second {
		t.Errorf("after Reset digest changed: %016x != %016x", first, second)
	}
}

// FuzzSipHash exercises the wrapper with arbitrary key bytes and data. It feeds
// the one-shot Hash/Hash128 forms unconditionally (they take uint64 key parts,
// so any length is safe) and the streaming New/New128 forms only for a valid
// 16-byte key, which is the documented requirement. The goal is to catch panics
// and any streaming/one-shot divergence on adversarial input.
func FuzzSipHash(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte("seed"))
	f.Add(make([]byte, 16), []byte{})
	f.Add([]byte("short"), []byte("odd key length"))
	f.Add(make([]byte, 16), make([]byte, 1535))

	f.Fuzz(func(t *testing.T, key, data []byte) {
		// One-shot forms: derive uint64 key parts from whatever bytes we have,
		// padding to 16 so Uint64 reads are in-bounds.
		var k [16]byte
		copy(k[:], key)
		k0 := binary.LittleEndian.Uint64(k[0:8])
		k1 := binary.LittleEndian.Uint64(k[8:16])

		oneShot := Hash(k0, k1, data)
		lo, hi := Hash128(k0, k1, data)

		// Streaming forms require an exactly-16-byte key (documented contract).
		if len(key) == 16 {
			h := New(key)
			h.Write(data)
			if got := h.Sum64(); got != oneShot {
				t.Fatalf("streaming %016x != one-shot %016x for %d bytes", got, oneShot, len(data))
			}

			h128 := New128(key)
			h128.Write(data)
			sum := h128.Sum(nil)
			if len(sum) != 16 {
				t.Fatalf("New128 Sum length = %d, want 16", len(sum))
			}
			if sLo := binary.LittleEndian.Uint64(sum[0:8]); sLo != lo {
				t.Fatalf("New128 lo %016x != Hash128 lo %016x", sLo, lo)
			}
			if sHi := binary.LittleEndian.Uint64(sum[8:16]); sHi != hi {
				t.Fatalf("New128 hi %016x != Hash128 hi %016x", sHi, hi)
			}
		}
	})
}
