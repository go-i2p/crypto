package rand

import (
	"math"
	"math/big"
	"testing"
)

func TestPRNG_NewSource(t *testing.T) {
	src := NewSource(42)
	if src == nil {
		t.Fatal("NewSource returned nil")
	}

	// Test that it implements Source interface
	_ = Source(src)

	// Test that it implements Source64 interface
	if _, ok := src.(Source64); !ok {
		t.Error("NewSource should return Source64 implementation")
	}
}

func TestPRNG_New(t *testing.T) {
	src := NewSource(42)
	r := New(src)
	if r == nil {
		t.Fatal("New returned nil")
	}
}

func TestPRNG_BasicFunctions(t *testing.T) {
	r := New(NewSource(42))

	// Test Int63
	i63 := r.Int63()
	if i63 < 0 {
		t.Error("Int63 returned negative value")
	}

	// Test Int31
	i31 := r.Int31()
	if i31 < 0 {
		t.Error("Int31 returned negative value")
	}

	// Test Int
	i := r.Int()
	if i < 0 {
		t.Error("Int returned negative value")
	}

	// Test Uint32
	u32 := r.Uint32()
	_ = u32 // Just test it doesn't panic

	// Test Uint64
	u64 := r.Uint64()
	_ = u64 // Just test it doesn't panic
}

func TestPRNG_RangedFunctions(t *testing.T) {
	r := New(NewSource(42))

	// Test Int63n
	for i := 0; i < 100; i++ {
		val := r.Int63n(100)
		if val < 0 || val >= 100 {
			t.Errorf("Int63n(100) returned %d, want [0,100)", val)
		}
	}

	// Test Int31n
	for i := 0; i < 100; i++ {
		val := r.Int31n(50)
		if val < 0 || val >= 50 {
			t.Errorf("Int31n(50) returned %d, want [0,50)", val)
		}
	}

	// Test Intn
	for i := 0; i < 100; i++ {
		val := r.Intn(25)
		if val < 0 || val >= 25 {
			t.Errorf("Intn(25) returned %d, want [0,25)", val)
		}
	}
}

func TestPRNG_FloatFunctions(t *testing.T) {
	r := New(NewSource(42))

	// Test Float64
	for i := 0; i < 100; i++ {
		val := r.Float64()
		if val < 0.0 || val >= 1.0 {
			t.Errorf("Float64() returned %f, want [0.0,1.0)", val)
		}
	}

	// Test Float32
	for i := 0; i < 100; i++ {
		val := r.Float32()
		if val < 0.0 || val >= 1.0 {
			t.Errorf("Float32() returned %f, want [0.0,1.0)", val)
		}
	}
}

func TestPRNG_Perm(t *testing.T) {
	r := New(NewSource(42))

	perm := r.Perm(10)
	if len(perm) != 10 {
		t.Errorf("Perm(10) returned slice of length %d, want 10", len(perm))
	}

	// Check all numbers 0-9 are present
	seen := make(map[int]bool)
	for _, v := range perm {
		if v < 0 || v >= 10 {
			t.Errorf("Perm(10) contains invalid value %d", v)
		}
		if seen[v] {
			t.Errorf("Perm(10) contains duplicate value %d", v)
		}
		seen[v] = true
	}

	if len(seen) != 10 {
		t.Errorf("Perm(10) missing values, got %d unique values", len(seen))
	}
}

func TestPRNG_Shuffle(t *testing.T) {
	r := New(NewSource(42))

	slice := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	original := make([]int, len(slice))
	copy(original, slice)

	r.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})

	// Check that all original elements are still there
	count := make(map[int]int)
	for _, v := range slice {
		count[v]++
	}
	for i := 0; i < 10; i++ {
		if count[i] != 1 {
			t.Errorf("After shuffle, value %d appears %d times", i, count[i])
		}
	}
}

func TestPRNG_DistributionFunctions(t *testing.T) {
	r := New(NewSource(42))

	// Test NormFloat64 - just check it doesn't panic and returns reasonable values
	for i := 0; i < 10; i++ {
		val := r.NormFloat64()
		if math.IsNaN(val) || math.IsInf(val, 0) {
			t.Errorf("NormFloat64() returned invalid value: %f", val)
		}
	}

	// Test ExpFloat64 - should return positive values
	for i := 0; i < 10; i++ {
		val := r.ExpFloat64()
		if val <= 0 || math.IsNaN(val) || math.IsInf(val, 0) {
			t.Errorf("ExpFloat64() returned invalid value: %f", val)
		}
	}
}

func TestPRNG_Seed(t *testing.T) {
	r1 := New(NewSource(42))
	r2 := New(NewSource(42))

	// With crypto/rand, same seed does NOT produce same sequence (for security)
	// This is different from math/rand but correct for cryptographic use
	val1a := r1.Int63()
	val2a := r2.Int63()
	// We don't require these to be equal since crypto/rand is used

	// Re-seeding is a no-op with crypto/rand but should not cause errors
	r1.Seed(42)
	val1b := r1.Int63()
	// We don't require val1a == val1b since crypto/rand ignores seeds

	// Just verify the values are valid (non-negative)
	if val1a < 0 || val1b < 0 || val2a < 0 {
		t.Error("Int63() should return non-negative values")
	}
}

func TestPRNG_GlobalFunctions(t *testing.T) {
	// Test that global functions work
	Seed(12345)

	// Test basic functions
	_ = Int63()
	_ = Int31()
	_ = Int()
	_ = Uint32()
	_ = Uint64()

	// Test ranged functions
	val := Intn(100)
	if val < 0 || val >= 100 {
		t.Errorf("Global Intn(100) returned %d, want [0,100)", val)
	}

	// Test float functions
	f64 := Float64()
	if f64 < 0.0 || f64 >= 1.0 {
		t.Errorf("Global Float64() returned %f, want [0.0,1.0)", f64)
	}

	f32 := Float32()
	if f32 < 0.0 || f32 >= 1.0 {
		t.Errorf("Global Float32() returned %f, want [0.0,1.0)", f32)
	}

	// Test other functions
	_ = Perm(5)
	_ = NormFloat64()
	_ = ExpFloat64()

	testSlice := []int{0, 1, 2, 3, 4}
	Shuffle(len(testSlice), func(i, j int) {
		testSlice[i], testSlice[j] = testSlice[j], testSlice[i]
	})
}

func TestPRNG_PanicCases(t *testing.T) {
	r := New(NewSource(42))

	// Test panics for invalid arguments
	defer func() {
		if r := recover(); r == nil {
			t.Error("Int63n(0) should panic")
		}
	}()
	r.Int63n(0)
}

func TestCryptoCompatibility(t *testing.T) {
	// Test that crypto/rand compatible functions work
	max := big.NewInt(1000)

	result, err := CryptoInt(Reader, max)
	if err != nil {
		t.Errorf("CryptoInt failed: %v", err)
	}

	if result.Cmp(big.NewInt(0)) < 0 || result.Cmp(max) >= 0 {
		t.Errorf("CryptoInt returned %v, want [0,%v)", result, max)
	}

	// Test Prime function
	prime, err := Prime(Reader, 64)
	if err != nil {
		t.Errorf("Prime failed: %v", err)
	}

	if prime.BitLen() != 64 {
		t.Errorf("Prime returned %d bits, want 64", prime.BitLen())
	}
}

// Benchmark tests
func BenchmarkPRNG_Int63(b *testing.B) {
	r := New(NewSource(42))
	for i := 0; i < b.N; i++ {
		r.Int63()
	}
}

func BenchmarkPRNG_Float64(b *testing.B) {
	r := New(NewSource(42))
	for i := 0; i < b.N; i++ {
		r.Float64()
	}
}

func BenchmarkPRNG_Intn(b *testing.B) {
	r := New(NewSource(42))
	for i := 0; i < b.N; i++ {
		r.Intn(1000)
	}
}

func BenchmarkGlobal_Int63(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Int63()
	}
}

func BenchmarkGlobal_Float64(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Float64()
	}
}
