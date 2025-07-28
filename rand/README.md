# rand
--
    import "github.com/go-i2p/crypto/rand"

![rand.svg](rand.svg)



## Usage

```go
const (
	// Minimum entropy threshold for random data (bits per byte)
	// Reduced to 4.0 for crypto/rand compatibility while still catching patterns
	MinEntropyThreshold = 4.0

	// Maximum retry attempts for entropy validation
	MaxEntropyRetries = 10

	// Sample size for entropy testing
	EntropySampleSize = 1024
)
```
Entropy validation constants

```go
var (
	ErrInsufficientEntropy = oops.Errorf("insufficient entropy in random source")
	ErrRandomReadFailed    = oops.Errorf("failed to read from random source")
	ErrEntropyValidation   = oops.Errorf("entropy validation failed")
)
```
Common errors for random number generation

```go
var DefaultSecureReader = NewSecureReader()
```
Global secure reader instance

```go
var Reader io.Reader = DefaultSecureReader
```
Reader is the global, shared instance of a cryptographically secure random
number generator Compatible with crypto/rand.Reader

#### func  CryptoInt

```go
func CryptoInt(reader io.Reader, max *big.Int) (*big.Int, error)
```
CryptoInt returns a uniform random value in [0, max). It panics if max <= 0.
Compatible with crypto/rand.Int function

#### func  ExpFloat64

```go
func ExpFloat64() float64
```
ExpFloat64 returns an exponentially distributed float64 with rate parameter 1

#### func  Float32

```go
func Float32() float32
```
Float32 returns, as a float32, a pseudo-random number in [0.0,1.0)

#### func  Float64

```go
func Float64() float64
```
Float64 returns, as a float64, a pseudo-random number in [0.0,1.0)

#### func  Int

```go
func Int() int
```
Int returns a non-negative pseudo-random int

#### func  Int31

```go
func Int31() int32
```
Int31 returns a non-negative pseudo-random 31-bit integer as an int32

#### func  Int31n

```go
func Int31n(n int32) int32
```
Int31n returns, as an int32, a non-negative pseudo-random number in [0,n)

#### func  Int63

```go
func Int63() int64
```
Int63 returns a non-negative pseudo-random 63-bit integer as an int64

#### func  Int63n

```go
func Int63n(n int64) int64
```
Int63n returns, as an int64, a non-negative pseudo-random number in [0,n)

#### func  Intn

```go
func Intn(n int) int
```
Intn returns, as an int, a non-negative pseudo-random number in [0,n)

#### func  NormFloat64

```go
func NormFloat64() float64
```
NormFloat64 returns a normally distributed float64 in the range
[-math.MaxFloat64, +math.MaxFloat64]

#### func  Perm

```go
func Perm(n int) []int
```
Perm returns, as a slice of n ints, a pseudo-random permutation of the integers
[0,n)

#### func  Prime

```go
func Prime(random io.Reader, bits int) (*big.Int, error)
```
Prime returns a number of the given bit length that is prime with high
probability. Compatible with crypto/rand.Prime function

#### func  Read

```go
func Read(p []byte) (n int, err error)
```
Read fills the provided byte slice with cryptographically secure random data

#### func  ReadBigInt

```go
func ReadBigInt(max *big.Int) (*big.Int, error)
```
ReadBigInt generates a cryptographically secure big.Int in the range [0, max)

#### func  ReadBigIntInRange

```go
func ReadBigIntInRange(min, max *big.Int) (*big.Int, error)
```
ReadBigIntInRange generates a cryptographically secure big.Int in the range
[min, max)

#### func  Seed

```go
func Seed(seed int64)
```
Seed uses the provided seed value to initialize the default Source

#### func  Shuffle

```go
func Shuffle(n int, swap func(i, j int))
```
Shuffle pseudo-randomizes the order of elements

#### func  Uint32

```go
func Uint32() uint32
```
Uint32 returns a pseudo-random 32-bit value as a uint32

#### func  Uint64

```go
func Uint64() uint64
```
Uint64 returns a pseudo-random 64-bit value as a uint64

#### type Rand

```go
type Rand struct {
}
```

Rand represents a source of random numbers with math/rand compatibility

#### func  New

```go
func New(src Source) *Rand
```
New returns a new Rand that uses random values from src Compatible with
math/rand.New

#### func (*Rand) ExpFloat64

```go
func (r *Rand) ExpFloat64() float64
```
ExpFloat64 returns an exponentially distributed float64 with rate parameter 1
Compatible with math/rand.ExpFloat64

#### func (*Rand) Float32

```go
func (r *Rand) Float32() float32
```
Float32 returns, as a float32, a pseudo-random number in [0.0,1.0) Compatible
with math/rand.Float32

#### func (*Rand) Float64

```go
func (r *Rand) Float64() float64
```
Float64 returns, as a float64, a pseudo-random number in [0.0,1.0) Compatible
with math/rand.Float64

#### func (*Rand) Int

```go
func (r *Rand) Int() int
```
Int returns a non-negative pseudo-random int Compatible with math/rand.Int

#### func (*Rand) Int31

```go
func (r *Rand) Int31() int32
```
Int31 returns a non-negative pseudo-random 31-bit integer as an int32 Compatible
with math/rand.Int31

#### func (*Rand) Int31n

```go
func (r *Rand) Int31n(n int32) int32
```
Int31n returns, as an int32, a non-negative pseudo-random number in [0,n)
Compatible with math/rand.Int31n

#### func (*Rand) Int63

```go
func (r *Rand) Int63() int64
```
Int63 returns a non-negative pseudo-random 63-bit integer as an int64 Compatible
with math/rand.Int63

#### func (*Rand) Int63n

```go
func (r *Rand) Int63n(n int64) int64
```
Int63n returns, as an int64, a non-negative pseudo-random number in [0,n)
Compatible with math/rand.Int63n

#### func (*Rand) Intn

```go
func (r *Rand) Intn(n int) int
```
Intn returns, as an int, a non-negative pseudo-random number in [0,n) Compatible
with math/rand.Intn

#### func (*Rand) NormFloat64

```go
func (r *Rand) NormFloat64() float64
```
NormFloat64 returns a normally distributed float64 in the range
[-math.MaxFloat64, +math.MaxFloat64] Compatible with math/rand.NormFloat64

#### func (*Rand) Perm

```go
func (r *Rand) Perm(n int) []int
```
Perm returns, as a slice of n ints, a pseudo-random permutation of the integers
[0,n) Compatible with math/rand.Perm

#### func (*Rand) Seed

```go
func (r *Rand) Seed(seed int64)
```
Seed uses the provided seed value to initialize the generator Compatible with
math/rand.Seed

#### func (*Rand) Shuffle

```go
func (r *Rand) Shuffle(n int, swap func(i, j int))
```
Shuffle pseudo-randomizes the order of elements using the Fisher-Yates shuffle
Compatible with math/rand.Shuffle

#### func (*Rand) Uint32

```go
func (r *Rand) Uint32() uint32
```
Uint32 returns a pseudo-random 32-bit value as a uint32 Compatible with
math/rand.Uint32

#### func (*Rand) Uint64

```go
func (r *Rand) Uint64() uint64
```
Uint64 returns a pseudo-random 64-bit value as a uint64 Compatible with
math/rand.Uint64

#### type SecureReader

```go
type SecureReader struct {
}
```

SecureReader provides cryptographically secure random number generation with
entropy validation for the go-i2p/crypto library

#### func  NewSecureReader

```go
func NewSecureReader() *SecureReader
```
NewSecureReader creates a new SecureReader using crypto/rand as the source

#### func (*SecureReader) Read

```go
func (sr *SecureReader) Read(p []byte) (n int, err error)
```
Read fills the provided byte slice with cryptographically secure random data and
validates entropy before returning

#### func (*SecureReader) ReadBigInt

```go
func (sr *SecureReader) ReadBigInt(max *big.Int) (*big.Int, error)
```
ReadBigInt generates a cryptographically secure big.Int in the range [0, max)

#### func (*SecureReader) ReadBigIntInRange

```go
func (sr *SecureReader) ReadBigIntInRange(min, max *big.Int) (*big.Int, error)
```
ReadBigIntInRange generates a cryptographically secure big.Int in the range
[min, max)

#### type Source

```go
type Source interface {
	Int63() int64
	Seed(seed int64)
}
```

Source is the interface for a source of random data Compatible with
math/rand.Source interface

#### func  NewSource

```go
func NewSource(seed int64) Source
```
NewSource returns a new pseudo-random Source seeded with the given value. Note:
Since we use crypto/rand, the seed is used for compatibility but doesn't affect
randomness Compatible with math/rand.NewSource

#### type Source64

```go
type Source64 interface {
	Source
	Uint64() uint64
}
```

Source64 extends Source to also provide Uint64. Compatible with
math/rand.Source64 interface



rand 

github.com/go-i2p/crypto/rand

[go-i2p template file](/template.md)
