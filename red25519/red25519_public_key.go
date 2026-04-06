package red25519

import (
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	upstream "github.com/go-i2p/red25519"
)

// Red25519PublicKey represents a Red25519 public key as a 32-byte compressed Edwards point.
//
// The key format is identical to standard Ed25519 (32 bytes), but verification
// is stricter: Red25519 rejects all small-order public keys (order dividing the
// cofactor 8) which would allow trivial or near-trivial signature forgery.
//
// CRITICAL: Always use NewRed25519PublicKey() to create instances.
//
// WRONG - Unsafe:
//
//	var key Red25519PublicKey  // Zero value - cryptographically invalid
//
// CORRECT - Use constructor:
//
//	pubKey, err := red25519.NewRed25519PublicKey(pubBytes)
//	if err != nil {
//	    return err
//	}
type Red25519PublicKey upstream.PublicKey

// NewVerifier creates a verifier instance that can validate Red25519 signatures.
// Returns a verifier configured with this public key for Red25519 signature verification.
// The verifier rejects small-order public keys for defense against forgery.
func (k Red25519PublicKey) NewVerifier() (v types.Verifier, err error) {
	temp := new(Red25519Verifier)
	temp.k = upstream.PublicKey(k)
	v = temp
	return temp, nil
}

// Len returns the length of the Red25519 public key in bytes.
// Red25519 public keys are always 32 bytes long.
func (k Red25519PublicKey) Len() int {
	return len(k)
}

// Bytes returns the raw byte representation of the Red25519 public key.
// The returned slice contains the 32-byte compressed Edwards point data suitable for
// serialization, transmission, or storage operations.
func (k Red25519PublicKey) Bytes() []byte {
	return k
}

// NewRed25519PublicKey creates a validated Red25519 public key from bytes.
// This is the REQUIRED constructor - do not use var declarations or direct construction.
//
// Parameters:
//   - data: Must be exactly 32 bytes representing a valid compressed Edwards point
//
// Returns error if data length is invalid.
func NewRed25519PublicKey(data []byte) (Red25519PublicKey, error) {
	log.WithFields(logger.Fields{"pkg": "red25519", "func": "NewRed25519PublicKey", "data_length": len(data)}).Debug("Creating Red25519 public key")

	if len(data) != PublicKeySize {
		log.WithFields(logger.Fields{"pkg": "red25519", "func": "NewRed25519PublicKey", "data_length": len(data)}).Error("Invalid Red25519 public key size")
		return nil, ErrInvalidPublicKeySize
	}

	key := make(Red25519PublicKey, PublicKeySize)
	copy(key, data)
	log.WithFields(logger.Fields{"pkg": "red25519", "func": "NewRed25519PublicKey"}).Debug("Red25519 public key created successfully")
	return key, nil
}
