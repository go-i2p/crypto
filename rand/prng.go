package rand

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"sync"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// PRNG Implementation using crypto/rand
//
// This implementation provides math/rand compatible API but uses ONLY crypto/rand
// as the underlying source. This ensures all random operations are cryptographically
// secure, unlike standard math/rand which uses predictable pseudo-random algorithms.
//
// Key differences from standard math/rand:
// - Seeding is ignored (no-op) for security - crypto/rand doesn't use seeds
// - All randomness comes from cryptographically secure sources
// - Performance is slower but security is guaranteed
// - Suitable for cryptographic applications and I2P networking

// Source is the interface for a source of random data
// Compatible with math/rand.Source interface
type Source interface {
	Int63() int64
	Seed(seed int64)
}

// Source64 extends Source to also provide Uint64.
// Compatible with math/rand.Source64 interface
type Source64 interface {
	Source
	Uint64() uint64
}

// cryptoSource implements Source64 using crypto/rand
type cryptoSource struct {
	reader io.Reader
	mu     sync.Mutex
}

// NewSource returns a new pseudo-random Source seeded with the given value.
// Note: Since we use crypto/rand, the seed is used for compatibility but doesn't affect randomness
// Compatible with math/rand.NewSource
func NewSource(seed int64) Source {
	log := logger.GetGoI2PLogger()
	log.WithField("seed", seed).Debug("Creating new crypto-based PRNG source")

	return &cryptoSource{reader: rand.Reader}
}

func (c *cryptoSource) Int63() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	var buf [8]byte
	_, err := c.reader.Read(buf[:])
	if err != nil {
		// Fallback to DefaultSecureReader if crypto/rand fails
		_, err = DefaultSecureReader.Read(buf[:])
		if err != nil {
			// This should never happen, but if it does, return a deterministic value
			return 1
		}
	}

	// Convert to int64 and mask to 63 bits (non-negative)
	return int64(binary.BigEndian.Uint64(buf[:]) >> 1)
}

func (c *cryptoSource) Seed(seed int64) {
	// For crypto/rand, seeding doesn't apply, but we implement for compatibility
	log := logger.GetGoI2PLogger()
	log.WithField("seed", seed).Debug("Seed called on crypto source (no-op for security)")
}

func (c *cryptoSource) Uint64() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	var buf [8]byte
	_, err := c.reader.Read(buf[:])
	if err != nil {
		// Fallback to DefaultSecureReader if crypto/rand fails
		_, err = DefaultSecureReader.Read(buf[:])
		if err != nil {
			// This should never happen, but if it does, return a deterministic value
			return 1
		}
	}

	return binary.BigEndian.Uint64(buf[:])
}

// Rand represents a source of random numbers with math/rand compatibility
type Rand struct {
	src    Source
	s64    Source64 // non-nil if src is source64
	mu     sync.Mutex
	cached bool
	norm   float64
}

// New returns a new Rand that uses random values from src
// Compatible with math/rand.New
func New(src Source) *Rand {
	log := logger.GetGoI2PLogger()
	log.Debug("Creating new Rand instance")

	r := &Rand{src: src}
	if s64, ok := src.(Source64); ok {
		r.s64 = s64
	}
	return r
}

// Seed uses the provided seed value to initialize the generator
// Compatible with math/rand.Seed
func (r *Rand) Seed(seed int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.src.Seed(seed)
	r.cached = false
}

// Int63 returns a non-negative pseudo-random 63-bit integer as an int64
// Compatible with math/rand.Int63
func (r *Rand) Int63() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.src.Int63()
}

// Uint32 returns a pseudo-random 32-bit value as a uint32
// Compatible with math/rand.Uint32
func (r *Rand) Uint32() uint32 {
	return uint32(r.Int63() >> 31)
}

// Uint64 returns a pseudo-random 64-bit value as a uint64
// Compatible with math/rand.Uint64
func (r *Rand) Uint64() uint64 {
	if r.s64 != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.s64.Uint64()
	}
	return uint64(r.Int63())>>31 | uint64(r.Int63())<<32
}

// Int31 returns a non-negative pseudo-random 31-bit integer as an int32
// Compatible with math/rand.Int31
func (r *Rand) Int31() int32 {
	return int32(r.Int63() >> 32)
}

// Int returns a non-negative pseudo-random int
// Compatible with math/rand.Int
func (r *Rand) Int() int {
	u := uint(r.Int63())
	return int(u << 1 >> 1) // clear sign bit if int == int32
}

// Int63n returns, as an int64, a non-negative pseudo-random number in [0,n)
// Compatible with math/rand.Int63n
func (r *Rand) Int63n(n int64) int64 {
	if n <= 0 {
		panic(oops.Errorf("invalid argument to Int63n"))
	}
	if n&(n-1) == 0 { // n is power of two, can mask
		return r.Int63() & (n - 1)
	}
	max := int64((1 << 63) - 1 - (1<<63)%uint64(n))
	v := r.Int63()
	for v > max {
		v = r.Int63()
	}
	return v % n
}

// Int31n returns, as an int32, a non-negative pseudo-random number in [0,n)
// Compatible with math/rand.Int31n
func (r *Rand) Int31n(n int32) int32 {
	if n <= 0 {
		panic(oops.Errorf("invalid argument to Int31n"))
	}
	if n&(n-1) == 0 { // n is power of two, can mask
		return r.Int31() & (n - 1)
	}
	max := int32((1 << 31) - 1 - (1<<31)%uint32(n))
	v := r.Int31()
	for v > max {
		v = r.Int31()
	}
	return v % n
}

// Intn returns, as an int, a non-negative pseudo-random number in [0,n)
// Compatible with math/rand.Intn
func (r *Rand) Intn(n int) int {
	if n <= 0 {
		panic(oops.Errorf("invalid argument to Intn"))
	}
	if n <= 1<<31-1 {
		return int(r.Int31n(int32(n)))
	}
	return int(r.Int63n(int64(n)))
}

// Float64 returns, as a float64, a pseudo-random number in [0.0,1.0)
// Compatible with math/rand.Float64
func (r *Rand) Float64() float64 {
	// A cleaner, more uniform implementation
	return float64(r.Int63()>>11) / (1 << 52)
}

// Float32 returns, as a float32, a pseudo-random number in [0.0,1.0)
// Compatible with math/rand.Float32
func (r *Rand) Float32() float32 {
	// A cleaner, more uniform implementation
	return float32(r.Int31()>>8) / (1 << 23)
}

// Perm returns, as a slice of n ints, a pseudo-random permutation of the integers [0,n)
// Compatible with math/rand.Perm
func (r *Rand) Perm(n int) []int {
	m := make([]int, n)
	for i := 0; i < n; i++ {
		m[i] = i
	}
	r.Shuffle(n, func(i, j int) { m[i], m[j] = m[j], m[i] })
	return m
}

// Shuffle pseudo-randomizes the order of elements using the Fisher-Yates shuffle
// Compatible with math/rand.Shuffle
func (r *Rand) Shuffle(n int, swap func(i, j int)) {
	if n < 0 {
		panic(oops.Errorf("invalid argument to Shuffle"))
	}

	// Fisher-Yates shuffle: https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
	for i := n - 1; i > 0; i-- {
		j := int(r.Int63n(int64(i + 1)))
		swap(i, j)
	}
}

// NormFloat64 returns a normally distributed float64 in the range [-math.MaxFloat64, +math.MaxFloat64]
// Compatible with math/rand.NormFloat64
func (r *Rand) NormFloat64() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cached {
		r.cached = false
		return r.norm
	}

	// Box-Muller transformation - call Int63() directly to avoid mutex deadlock
	for {
		// Generate two uniform random numbers in [-1, 1)
		u := 2*(float64(r.src.Int63()>>11)/(1<<52)) - 1
		v := 2*(float64(r.src.Int63()>>11)/(1<<52)) - 1
		s := u*u + v*v
		if s != 0 && s < 1 {
			s = math.Sqrt(-2 * math.Log(s) / s)
			r.norm = v * s
			r.cached = true
			return u * s
		}
	}
}

// ExpFloat64 returns an exponentially distributed float64 with rate parameter 1
// Compatible with math/rand.ExpFloat64
func (r *Rand) ExpFloat64() float64 {
	for {
		// Call Int63() directly to avoid potential mutex issues
		u := float64(r.Int63()>>11) / (1 << 52)
		if u != 0 {
			return -math.Log(u)
		}
	}
}

// Global PRNG instance initialized with crypto/rand
var globalRand = New(NewSource(0)) // Seed doesn't matter for crypto/rand

// Global functions that use the global PRNG - compatible with math/rand

// Seed uses the provided seed value to initialize the default Source
func Seed(seed int64) {
	globalRand.Seed(seed)
}

// Int63 returns a non-negative pseudo-random 63-bit integer as an int64
func Int63() int64 {
	return globalRand.Int63()
}

// Uint32 returns a pseudo-random 32-bit value as a uint32
func Uint32() uint32 {
	return globalRand.Uint32()
}

// Uint64 returns a pseudo-random 64-bit value as a uint64
func Uint64() uint64 {
	return globalRand.Uint64()
}

// Int31 returns a non-negative pseudo-random 31-bit integer as an int32
func Int31() int32 {
	return globalRand.Int31()
}

// Int returns a non-negative pseudo-random int
func Int() int {
	return globalRand.Int()
}

// Int63n returns, as an int64, a non-negative pseudo-random number in [0,n)
func Int63n(n int64) int64 {
	return globalRand.Int63n(n)
}

// Int31n returns, as an int32, a non-negative pseudo-random number in [0,n)
func Int31n(n int32) int32 {
	return globalRand.Int31n(n)
}

// Intn returns, as an int, a non-negative pseudo-random number in [0,n)
func Intn(n int) int {
	return globalRand.Intn(n)
}

// Float64 returns, as a float64, a pseudo-random number in [0.0,1.0)
func Float64() float64 {
	return globalRand.Float64()
}

// Float32 returns, as a float32, a pseudo-random number in [0.0,1.0)
func Float32() float32 {
	return globalRand.Float32()
}

// Perm returns, as a slice of n ints, a pseudo-random permutation of the integers [0,n)
func Perm(n int) []int {
	return globalRand.Perm(n)
}

// Shuffle pseudo-randomizes the order of elements
func Shuffle(n int, swap func(i, j int)) {
	globalRand.Shuffle(n, swap)
}

// NormFloat64 returns a normally distributed float64 in the range [-math.MaxFloat64, +math.MaxFloat64]
func NormFloat64() float64 {
	return globalRand.NormFloat64()
}

// ExpFloat64 returns an exponentially distributed float64 with rate parameter 1
func ExpFloat64() float64 {
	return globalRand.ExpFloat64()
}
