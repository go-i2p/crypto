# Secure Random Number Generation Package

This package provides cryptographically secure random number generation with entropy validation for the go-i2p/crypto library.

## Features

- **Cryptographically Secure**: Uses `crypto/rand` as the underlying random source
- **Entropy Validation**: Validates entropy for larger samples to ensure randomness quality
- **Big Integer Support**: Secure generation of `big.Int` values with range validation
- **Error Handling**: Comprehensive error handling with structured logging
- **Retry Logic**: Automatic retry on entropy validation failures

## Usage

### Basic Random Bytes

```go
import "github.com/go-i2p/crypto/rand"

// Generate 32 random bytes
buf := make([]byte, 32)
n, err := rand.Read(buf)
if err != nil {
    log.Fatal(err)
}
```

### Secure Big Integer Generation

```go
// Generate random big.Int in range [0, max)
max := big.NewInt(1000)
randomNum, err := rand.ReadBigInt(max)
if err != nil {
    log.Fatal(err)
}

// Generate random big.Int in range [min, max)
min := big.NewInt(100)
max := big.NewInt(1000)
randomNum, err := rand.ReadBigIntInRange(min, max)
if err != nil {
    log.Fatal(err)
}
```

### Advanced Usage with SecureReader

```go
// Create custom SecureReader instance
sr := rand.NewSecureReader()

// Use for multiple operations
buf := make([]byte, 64)
n, err := sr.Read(buf)
if err != nil {
    log.Fatal(err)
}

randomBigInt, err := sr.ReadBigInt(big.NewInt(2048))
if err != nil {
    log.Fatal(err)
}
```

## Security Features

### Entropy Validation
- Validates Shannon entropy for samples >= 32 bytes
- Minimum entropy threshold of 6.0 bits per byte
- Automatic retry on entropy validation failures

### Secure Big Integer Generation
- Uses `crypto/rand.Int` for secure generation
- Validates generated values are within specified ranges
- Prevents timing attacks through consistent operation patterns

### Error Handling
- Structured error handling with `github.com/samber/oops`
- Comprehensive logging for debugging and monitoring
- Retry logic with configurable maximum attempts

## Constants

- `MinEntropyThreshold`: 6.0 bits per byte minimum entropy
- `MaxEntropyRetries`: 10 maximum retry attempts for entropy validation
- `EntropySampleSize`: 1024 bytes sample size for entropy testing

## Thread Safety

All functions and methods in this package are thread-safe and can be used concurrently from multiple goroutines.

## Performance

The package is optimized for cryptographic security over raw performance. Entropy validation adds minimal overhead for most use cases, and can be bypassed for small samples (< 32 bytes).

## Integration with I2P Cryptography

This package is specifically designed for use with I2P cryptographic operations:
- ElGamal key generation
- DSA/ECDSA key generation  
- Symmetric key generation
- Nonce and IV generation

## Testing

Run tests with:
```bash
go test -v ./rand/
```

Run benchmarks with:
```bash
go test -bench=. ./rand/
```
