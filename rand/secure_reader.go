package rand

import (
	"crypto/rand"
	"io"
	"math"
	"math/big"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SecureReader provides cryptographically secure random number generation
// with entropy validation for the go-i2p/crypto library
type SecureReader struct {
	source io.Reader
}

// NewSecureReader creates a new SecureReader using crypto/rand as the source
func NewSecureReader() *SecureReader {
	return &SecureReader{
		source: rand.Reader,
	}
}

// Read fills the provided byte slice with cryptographically secure random data
// and validates entropy before returning
func (sr *SecureReader) Read(p []byte) (n int, err error) {
	log := logger.GetGoI2PLogger()

	for attempt := 0; attempt < MaxEntropyRetries; attempt++ {
		// Read random bytes from crypto/rand
		n, err = sr.source.Read(p)
		if err != nil {
			log.WithError(err).Error("Failed to read from secure random source")
			return 0, oops.Errorf("random read failed: %w", err)
		}

		// Validate entropy for larger samples
		if len(p) >= 32 {
			if !sr.validateEntropy(p) {
				log.WithField("attempt", attempt+1).Debug("Entropy validation failed, retrying")
				continue
			}
		}

		log.WithField("bytes_read", n).Debug("Successfully generated secure random bytes")
		return n, nil
	}

	err = oops.Errorf("entropy validation failed after %d attempts", MaxEntropyRetries)
	log.WithError(err).Error("Secure random generation failed")
	return 0, err
}

// ReadBigInt generates a cryptographically secure big.Int in the range [0, max)
func (sr *SecureReader) ReadBigInt(max *big.Int) (*big.Int, error) {
	log := logger.GetGoI2PLogger()

	if max.Sign() <= 0 {
		return nil, oops.Errorf("max must be positive")
	}

	for attempt := 0; attempt < MaxEntropyRetries; attempt++ {
		// Use crypto/rand.Int for secure big integer generation
		result, err := rand.Int(sr.source, max)
		if err != nil {
			log.WithError(err).Error("Failed to generate secure big.Int")
			return nil, oops.Errorf("big.Int generation failed: %w", err)
		}

		// Additional validation: ensure result is in valid range
		if result.Cmp(big.NewInt(0)) >= 0 && result.Cmp(max) < 0 {
			log.WithField("max_bits", max.BitLen()).Debug("Successfully generated secure big.Int")
			return result, nil
		}

		log.WithField("attempt", attempt+1).Debug("Generated big.Int outside valid range, retrying")
	}

	err := oops.Errorf("failed to generate valid big.Int after %d attempts", MaxEntropyRetries)
	log.WithError(err).Error("Secure big.Int generation failed")
	return nil, err
}

// ReadBigIntInRange generates a cryptographically secure big.Int in the range [min, max)
func (sr *SecureReader) ReadBigIntInRange(min, max *big.Int) (*big.Int, error) {
	log := logger.GetGoI2PLogger()

	if min.Cmp(max) >= 0 {
		return nil, oops.Errorf("min must be less than max")
	}

	// Calculate the range
	rangeSize := new(big.Int).Sub(max, min)

	// Generate random number in [0, rangeSize)
	randomInRange, err := sr.ReadBigInt(rangeSize)
	if err != nil {
		return nil, oops.Errorf("failed to generate random in range: %w", err)
	}

	// Add min to get result in [min, max)
	result := new(big.Int).Add(min, randomInRange)

	log.WithFields(map[string]interface{}{
		"min":    min.String(),
		"max":    max.String(),
		"result": result.String(),
	}).Debug("Successfully generated secure big.Int in range")

	return result, nil
}

// validateEntropy performs basic entropy validation on random data
func (sr *SecureReader) validateEntropy(data []byte) bool {
	if len(data) < 32 {
		return true // Skip validation for small samples
	}

	// For crypto/rand, we can trust the entropy but still do basic validation
	// Calculate Shannon entropy
	frequency := make(map[byte]int)
	for _, b := range data {
		frequency[b]++
	}

	// Check for obvious patterns (e.g., all same byte)
	if len(frequency) <= 1 {
		return false
	}

	entropy := 0.0
	length := float64(len(data))

	for _, count := range frequency {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy >= MinEntropyThreshold
}

// Global secure reader instance
var DefaultSecureReader = NewSecureReader()

// Reader is the global, shared instance of a cryptographically secure random number generator
// Compatible with crypto/rand.Reader
var Reader io.Reader = DefaultSecureReader

// CryptoInt returns a uniform random value in [0, max). It panics if max <= 0.
// Compatible with crypto/rand.Int function
func CryptoInt(reader io.Reader, max *big.Int) (*big.Int, error) {
	if max.Sign() <= 0 {
		return nil, oops.Errorf("max must be positive")
	}

	if sr, ok := reader.(*SecureReader); ok {
		return sr.ReadBigInt(max)
	}

	// Fallback to crypto/rand.Int for other readers
	return rand.Int(reader, max)
}

// Prime returns a number of the given bit length that is prime with high probability.
// Compatible with crypto/rand.Prime function
func Prime(random io.Reader, bits int) (*big.Int, error) {
	log := logger.GetGoI2PLogger()

	if bits < 2 {
		return nil, oops.Errorf("prime size must be at least 2 bits")
	}

	// Use crypto/rand.Prime as the underlying implementation
	prime, err := rand.Prime(random, bits)
	if err != nil {
		log.WithError(err).Error("Failed to generate prime number")
		return nil, oops.Errorf("prime generation failed: %w", err)
	}

	log.WithField("bits", bits).Debug("Successfully generated prime number")
	return prime, nil
}

// Read fills the provided byte slice with cryptographically secure random data
func Read(p []byte) (n int, err error) {
	return DefaultSecureReader.Read(p)
}

// ReadBigInt generates a cryptographically secure big.Int in the range [0, max)
func ReadBigInt(max *big.Int) (*big.Int, error) {
	return DefaultSecureReader.ReadBigInt(max)
}

// ReadBigIntInRange generates a cryptographically secure big.Int in the range [min, max)
func ReadBigIntInRange(min, max *big.Int) (*big.Int, error) {
	return DefaultSecureReader.ReadBigIntInRange(min, max)
}
