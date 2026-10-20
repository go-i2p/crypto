package hkdf

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// log provides structured logging for HKDF package operations.
// This logger instance is configured for the go-i2p/crypto HKDF module and enables
// debugging of key derivation processes and error tracking.
var log = logger.GetGoI2PLogger()

// Common HKDF errors
var (
	// ErrInvalidKeyLength indicates that the requested key derivation length is
	// invalid. This error is returned when the key length parameter is zero or
	// negative. An over-long request (beyond 255 * hash_length per RFC 5869) is
	// not caught here; it surfaces later as ErrKeyDerivationFailed.
	ErrInvalidKeyLength = oops.Errorf("invalid key length")

	// ErrInvalidSaltLength indicates that the provided salt parameter has an
	// invalid length. It is reserved and is not currently returned by this
	// package: HKDF accepts any salt length, including empty.
	ErrInvalidSaltLength = oops.Errorf("invalid salt length")

	// ErrInvalidInfoLength indicates that the info parameter exceeds maximum allowed length.
	// This package limits the info parameter to 255 bytes as an implementation-defined
	// safety bound; RFC 5869 itself places no length limit on info.
	ErrInvalidInfoLength = oops.Errorf("invalid info length")

	// ErrKeyDerivationFailed indicates that the HKDF key derivation process failed.
	// This error wraps underlying failures in the HKDF-Extract or HKDF-Expand phases,
	// typically due to insufficient entropy or implementation errors.
	ErrKeyDerivationFailed = oops.Errorf("key derivation failed")
)

// Default parameters for I2P compatibility
const (
	// DefaultKeyLength specifies the default derived key length for I2P operations.
	// Set to 32 bytes (256 bits) to provide optimal security for ChaCha20 symmetric encryption
	// and other I2P cryptographic primitives that require 256-bit keys.
	DefaultKeyLength = 32 // 256 bits for ChaCha20

	// MaxInfoLength defines the maximum allowed length for the HKDF info parameter.
	//
	// This is a local defensive bound, NOT a specification requirement. RFC 5869
	// §3.1 places no limit on the length of Info; its only size cap is in §3.2 /
	// §4 on the output length L, which is bounded at 255 * HashLen bytes. I2P
	// likewise imposes no info limit: ECIES-X25519-AEAD-Ratchet §4 "HKDF"
	// (https://i2p.net/en/docs/specs/ecies/) constrains only the salt
	// ("a salt of length 32 bytes ... This means that SALT_LEN is 32 bytes max")
	// and the output length.
	//
	// The value is chosen to match the largest info string any I2P label can need
	// (the longest label in the specs is 18 bytes), so it cannot reject a valid
	// I2P derivation. It is not a statement about what the spec requires.
	MaxInfoLength = 255 // local defensive bound; RFC 5869 sets no info limit
)
