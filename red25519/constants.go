package red25519

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

const (
	// PublicKeySize is the size in bytes of a Red25519 public key.
	//
	// red25519.md §Encoding and decoding: public keys are "encoded as the 255-bit
	// little-endian representation of the y-coordinate, followed by a single bit
	// indicating the sign of the x-coordinate. This is the same encoding as for
	// Ed25519" - 32 bytes. common-structures.md §SigningPublicKey agrees.
	PublicKeySize = 32

	// PrivateKeySize is the size in bytes of a Red25519 private key as the I2P
	// specification serializes it.
	//
	// red25519.md §Encoding and decoding: "Red25519 private keys are scalars mod
	// L, encoded in little-endian representation" - 32 bytes. This matches
	// common-structures.md §SigningPrivateKey, which lists
	// "RedDSA_SHA512_Ed25519 | 32 | 0.9.39".
	//
	// Note this is NOT Go's crypto/ed25519 layout (64-byte seed||public). Red25519
	// scalars are reduced mod L and never clamped: "Red25519 private keys are
	// generated from random numbers and then must be reduced mod L ... Ed25519
	// private keys are generated from random numbers and then 'clamped' using
	// bitwise masking to bytes 0 and 31. This is not done for Red25519."
	PrivateKeySize = 32

	// ScalarSize is the encoded length of a scalar mod L.
	ScalarSize = 32

	// SignatureSize is the size in bytes of a Red25519 signature:
	// SIGN returns "Rbytes || ENCODE_SCALAR(S)", i.e. a 32-byte encoded point
	// followed by a 32-byte encoded scalar. common-structures.md §Signature lists
	// RedDSA_SHA512_Ed25519 as 64 bytes.
	SignatureSize = PublicKeySize + ScalarSize

	// SeedSize is the length of the 32-byte value GENERATE_PRIVATE draws from.
	// Retained for API compatibility; Red25519 key generation consumes 64 random
	// bytes and reduces them mod L, so a caller-supplied 32-byte "seed" is not a
	// spec concept the way it is for Ed25519.
	SeedSize = 32

	// Ed25519ExpandedPrivateKeySize is Go's crypto/ed25519 private key length
	// (seed || public). Accepted only by [ConvertEd25519PrivateKey], which is
	// defined in terms of the 32-byte seed.
	Ed25519ExpandedPrivateKeySize = 64

	// NonceSizeT is the width of the random value T in SIGN: "T = 80 random
	// bytes". Exposed so a caller can generate the nonce itself and produce a
	// reproducible signature for testing.
	NonceSizeT = nonceSizeT

	// MaxMessageSize is the largest signable message: "Messages must be no longer
	// than 65534 bytes. A length of 65535 is reserved for possible future
	// extensions." (red25519.md §Red25519)
	MaxMessageSize = maxMessageSize
)

// log provides the logger instance for Red25519 package operations and debugging.
var log = logger.GetGoI2PLogger()

// Error constants for Red25519 operations.
var (
	// ErrInvalidPublicKeySize indicates a Red25519 public key is not a 32-byte
	// encoded point.
	ErrInvalidPublicKeySize = oops.Errorf("failed to verify: invalid red25519 public key size")

	// ErrInvalidPrivateKeySize indicates a Red25519 private key is not a 32-byte
	// scalar encoding.
	ErrInvalidPrivateKeySize = oops.Errorf("invalid red25519 private key size")

	// ErrInvalidSignatureSize indicates a Red25519 signature is not 64 bytes.
	ErrInvalidSignatureSize = oops.Errorf("invalid red25519 signature size")

	// ErrMessageTooLong indicates a message exceeds the Red25519 maximum of 65534
	// bytes, over which the 2-byte little-endian length prefix is ambiguous.
	ErrMessageTooLong = oops.Errorf("message exceeds the Red25519 maximum of %d bytes", MaxMessageSize)

	// ErrSmallOrderPoint indicates a point that is not in the prime-order
	// subgroup. encryptedleaseset.md §Goals requires "Blinded public keys must be
	// on the Ed25519 curve and prime-order subgroup".
	ErrSmallOrderPoint = oops.Errorf("point is not in the prime-order subgroup")
)
