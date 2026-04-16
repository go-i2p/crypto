package argon2

/**
 * This package implements the KeyDeriver interface using the Argon2id key derivation function.
 * Argon2id is a memory-hard function designed to resist GPU and ASIC attacks, making it suitable for password hashing and key derivation.
 * It combines the features of Argon2i (optimized for password hashing) and Argon2d (optimized for resistance against side-channel attacks).
 *
 * The implementation provides both a flexible Derive method that allows customization of parameters such as salt and info,
 * and a DeriveDefault method that uses standard parameters for common use cases.
 *
 * Usage:
 *   - To derive a key with custom parameters:
 *     derivedKey, err := argon2id.Derive(ikm, salt, info, keyLen)
 *
 *   - To derive a key with default parameters:
 *     derivedKey, err := argon2id.DeriveDefault(ikm)
 *
 * The package ensures that the derived keys are generated securely and efficiently, adhering to best practices for key derivation.
 *
 * In I2P, argon2id could be used for Proof-of-Work in tunnel build requests.
 *
 * This implementation uses golang.org/x/crypto/argon2 for the underlying Argon2id algorithm, providing a robust and well-tested foundation for key derivation.
 */

import (
	"github.com/go-i2p/logger"

	"golang.org/x/crypto/argon2"
)

type Argon2id struct {
	TimeCost    uint32
	MemoryCost  uint32
	Parallelism uint8
}

func NewArgon2id(timeCost, memoryCost uint32, parallelism uint8) *Argon2id {
	log.WithFields(logger.Fields{"pkg": "argon2", "func": "NewArgon2id"}).Debug("Creating new Argon2id instance")
	return &Argon2id{
		TimeCost:    timeCost,
		MemoryCost:  memoryCost,
		Parallelism: parallelism,
	}
}

// validateDeriveParams checks that all Argon2id derivation parameters meet
// minimum requirements before performing the expensive key derivation operation.
func validateDeriveParams(keyLen int, salt []byte, timeCost, memoryCost uint32, parallelism uint8) error {
	log.WithFields(logger.Fields{"pkg": "argon2", "func": "validateDeriveParams", "key_len": keyLen}).Debug("Validating Argon2id parameters")
	if keyLen <= 0 {
		log.WithFields(logger.Fields{"pkg": "argon2", "func": "validateDeriveParams"}).Error("Invalid key length")
		return ErrInvalidKeyLength
	}
	if len(salt) == 0 {
		return ErrInvalidSalt
	}
	if timeCost < 1 {
		return ErrInvalidTimeCost
	}
	if memoryCost < 8*1024 {
		return ErrInsufficientMemory
	}
	if parallelism == 0 {
		return ErrInvalidParallelism
	}
	return nil
}

// Derive derives a key of the specified length from the input key material (IKM) using Argon2id.
func (a *Argon2id) Derive(ikm, salt, info []byte, keyLen int) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "argon2", "func": "Argon2id.Derive", "key_len": keyLen}).Debug("Deriving key with Argon2id")
	if err := validateDeriveParams(keyLen, salt, a.TimeCost, a.MemoryCost, a.Parallelism); err != nil {
		log.WithFields(logger.Fields{"pkg": "argon2", "func": "Argon2id.Derive"}).WithError(err).Error("Parameter validation failed")
		return nil, err
	}
	derivedKey := argon2.IDKey(ikm, salt, a.TimeCost, a.MemoryCost, a.Parallelism, uint32(keyLen))
	log.WithFields(logger.Fields{"pkg": "argon2", "func": "Argon2id.Derive"}).Debug("Key derived successfully")
	return derivedKey, nil
}

// DeriveDefault derives a key using default parameters for common use cases.
func (a *Argon2id) DeriveDefault(ikm []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "argon2", "func": "Argon2id.DeriveDefault"}).Debug("Deriving key with default parameters")
	// Use default parameters: no salt, no info context, and a standard key length of 32 bytes
	return a.Derive(ikm, nil, nil, 32)
}

// Argon2idKDF is a convenient instance of the Argon2id key derivation function that can be used directly.
var Argon2idKDF = NewArgon2id(defaultTimeCost, defaultMemoryCost, defaultParallelism)
