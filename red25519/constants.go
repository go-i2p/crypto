package red25519

import (
	"github.com/go-i2p/logger"
	upstream "github.com/go-i2p/red25519"
	"github.com/samber/oops"
)

const (
	// PublicKeySize is the size in bytes of a Red25519 public key (32-byte compressed point).
	PublicKeySize = upstream.PublicKeySize

	// PrivateKeySize is the size in bytes of a Red25519 private key (64-byte seed+pubkey).
	PrivateKeySize = upstream.PrivateKeySize

	// SignatureSize is the size in bytes of a Red25519 signature (R || S).
	SignatureSize = upstream.SignatureSize

	// SeedSize is the size in bytes of private key seeds.
	SeedSize = upstream.SeedSize

	// BlindedPrivateKeySize is the size in bytes of a blinded Red25519 private key
	// (seed + pubkey + blinding factor = 96 bytes).
	BlindedPrivateKeySize = 96
)

// log provides the logger instance for Red25519 package operations and debugging.
var log = logger.GetGoI2PLogger()

// Error constants for Red25519 operations.
var (
	// ErrInvalidPublicKeySize indicates a Red25519 public key does not meet the required 32-byte size.
	ErrInvalidPublicKeySize = oops.Errorf("failed to verify: invalid red25519 public key size")

	// ErrInvalidPrivateKeySize indicates a Red25519 private key does not meet the required 64-byte size.
	ErrInvalidPrivateKeySize = oops.Errorf("invalid red25519 private key size")

	// ErrInvalidSignatureSize indicates a Red25519 signature does not meet the required 64-byte size.
	ErrInvalidSignatureSize = oops.Errorf("invalid red25519 signature size")
)
