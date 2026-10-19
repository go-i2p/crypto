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

// ErrorSource is implemented by sources that can report CSPRNG failure instead of
// panicking. [cryptoSource] implements it; expose it through the package-level
// [Int63Err]/[Uint64Err] helpers and [Rand.Int63Err]/[Rand.Uint64Err] so callers
// deriving key or nonce material can handle a dead entropy source explicitly.
//
// This exists because the math/rand-compatible [Source.Int63]/[Source64.Uint64]
// signatures have no error channel, and silently returning a fixed value on
// failure is unsafe for cryptographic use (encryptedleaseset.md §Definitions
// requires CSRNG output suitable for generating key material).
type ErrorSource interface {
	Int63Err() (int64, error)
	Uint64Err() (uint64, error)
}

// cryptoSource implements Source64 using crypto/rand
type cryptoSource struct {
	reader io.Reader
	mu     sync.Mutex
}

// NewSource returns a new Source backed by crypto/rand.
// The seed parameter is accepted for compatibility with math/rand.NewSource but
// is ignored: the returned Source draws from the cryptographic random reader, so
// output is not reproducible for a given seed.
// Compatible with math/rand.NewSource
func NewSource(seed int64) Source {
	log.WithFields(logger.Fields{"pkg": "rand", "func": "NewSource", "seed": seed}).Debug("Creating new crypto-based PRNG source")

	return &cryptoSource{reader: rand.Reader}
}

// read fills buf from the CSPRNG, falling back to DefaultSecureReader. It
// returns the underlying error instead of substituting a constant, so a caller
// that can handle failure (Int63Err/Uint64Err/Read) learns the entropy source is
// dead rather than silently building key material from a fixed value.
func (c *cryptoSource) read(buf []byte) error {
	if _, err := c.reader.Read(buf); err != nil {
		if _, err2 := DefaultSecureReader.Read(buf); err2 != nil {
			return oops.Wrapf(err2, "crypto/rand and DefaultSecureReader both failed: %v", err)
		}
	}
	return nil
}

func (c *cryptoSource) Int63() int64 {
	n, err := c.Int63Err()
	if err != nil {
		// The math/rand-compatible signature has no error channel. Returning a
		// constant here (the previous behaviour) let callers silently derive key
		// or nonce material from a fixed value - the worst failure mode for a
		// randomness abstraction. Fail loudly and non-recoverably instead; use
		// Int63Err to handle the failure. See encryptedleaseset.md §Definitions,
		// which requires CSRNG output to be "cryptographically-secure (and thus
		// suitable for generating key material)".
		panic(err)
	}
	return n
}

// Int63Err returns a non-negative pseudo-random 63-bit integer and any error
// from the underlying CSPRNG. Prefer it over [cryptoSource.Int63] wherever key
// or nonce material is derived, since Int63 panics rather than reporting failure.
func (c *cryptoSource) Int63Err() (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var buf [8]byte
	if err := c.read(buf[:]); err != nil {
		return 0, err
	}

	// Convert to int64 and mask to 63 bits (non-negative). Shifting the full
	// 64-bit read right by one discards a single bit; the result stays uniform
	// over [0, 2^63) and keeps the value non-negative.
	return int64(binary.BigEndian.Uint64(buf[:]) >> 1), nil
}

func (c *cryptoSource) Seed(seed int64) {
	// For crypto/rand, seeding doesn't apply, but we implement for compatibility
	log.WithFields(logger.Fields{"pkg": "rand", "func": "cryptoSource.Seed", "seed": seed}).Debug("Seed called on crypto source (no-op for security)")
}

func (c *cryptoSource) Uint64() uint64 {
	n, err := c.Uint64Err()
	if err != nil {
		// Same rationale as Int63: never substitute a constant for CSPRNG output.
		panic(err)
	}
	return n
}

// Uint64Err returns a pseudo-random 64-bit value and any error from the
// underlying CSPRNG. Prefer it over [cryptoSource.Uint64] for key material.
func (c *cryptoSource) Uint64Err() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var buf [8]byte
	if err := c.read(buf[:]); err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint64(buf[:]), nil
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
	log.WithFields(logger.Fields{"pkg": "rand", "func": "New"}).Debug("Creating new Rand instance")

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

// Int63Err returns a non-negative pseudo-random 63-bit integer and any CSPRNG
// error, if the underlying source implements [ErrorSource]. If it does not, it
// falls back to [Rand.Int63] with a nil error. Prefer this over Int63 when the
// value is used as key or nonce material.
func (r *Rand) Int63Err() (int64, error) {
	if es, ok := r.src.(ErrorSource); ok {
		r.mu.Lock()
		defer r.mu.Unlock()
		return es.Int63Err()
	}
	return r.Int63(), nil
}

// Uint64Err returns a pseudo-random 64-bit integer and any CSPRNG error, if the
// underlying source implements [ErrorSource]. See [Rand.Int63Err].
func (r *Rand) Uint64Err() (uint64, error) {
	if es, ok := r.src.(ErrorSource); ok {
		r.mu.Lock()
		defer r.mu.Unlock()
		return es.Uint64Err()
	}
	return r.Uint64(), nil
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

// boundedRand performs rejection sampling to return a uniformly distributed
// non-negative pseudo-random int64 in [0, n) using the given bit width and
// generator function, consolidating the shared logic of Int63n and Int31n.
func (r *Rand) boundedRand(n int64, bits uint, gen func() int64) int64 {
	if n&(n-1) == 0 { // n is power of two, can mask
		return gen() & (n - 1)
	}
	max := int64((uint64(1) << bits) - 1 - (uint64(1)<<bits)%uint64(n))
	v := gen()
	for v > max {
		v = gen()
	}
	return v % n
}

// Int63n returns, as an int64, a non-negative pseudo-random number in [0,n)
// Compatible with math/rand.Int63n
func (r *Rand) Int63n(n int64) int64 {
	if n <= 0 {
		panic(oops.Errorf("invalid argument to Int63n"))
	}
	return r.boundedRand(n, 63, r.Int63)
}

// Int31n returns, as an int32, a non-negative pseudo-random number in [0,n)
// Compatible with math/rand.Int31n
func (r *Rand) Int31n(n int32) int32 {
	if n <= 0 {
		panic(oops.Errorf("invalid argument to Int31n"))
	}
	return int32(r.boundedRand(int64(n), 31, func() int64 { return int64(r.Int31()) }))
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

// Int63Err returns a non-negative pseudo-random 63-bit integer and any CSPRNG
// error from the default source. Prefer it over [Int63] when the value is used
// for key or nonce material, since Int63 panics rather than reporting failure.
func Int63Err() (int64, error) {
	return globalRand.Int63Err()
}

// Uint64Err returns a pseudo-random 64-bit value and any CSPRNG error from the
// default source. See [Int63Err].
func Uint64Err() (uint64, error) {
	return globalRand.Uint64Err()
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

// Compile-time proof that the CSPRNG source offers both the math/rand-compatible
// shape and the error-reporting shape.
var (
	_ Source64    = (*cryptoSource)(nil)
	_ ErrorSource = (*cryptoSource)(nil)
)
