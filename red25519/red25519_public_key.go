package red25519

import (
	"filippo.io/edwards25519"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Red25519PublicKey is a Red25519 public key: a point on the Edwards form of
// Curve25519, encoded as the 32-byte little-endian y-coordinate with the sign of
// x in the top bit (red25519.md §Encoding and decoding: "the same encoding as for
// Ed25519").
//
// CRITICAL: Always use [NewRed25519PublicKey] to create instances.
type Red25519PublicKey []byte

// NewRed25519PublicKey validates and stores a 32-byte encoded Red25519 public
// point.
//
// The point must decode on the curve. It must also be in the prime-order
// subgroup: encryptedleaseset.md §Goals requires "Blinded public keys must be on
// the Ed25519 curve and prime-order subgroup", and a small-order (cofactor)
// component would let an attacker forge against a key whose public component the
// holder does not know the discrete log of. The check is [8]A != identity test
// being the identity only for the order-1 subgroup element combined with the
// requirement that A is not a torsion point; see the note in NewVerifier for how
// verification itself tolerates 8-torsion in R but not in the key.
func NewRed25519PublicKey(data []byte) (Red25519PublicKey, error) {
	log.WithFields(logger.Fields{"pkg": "red25519", "func": "NewRed25519PublicKey", "data_length": len(data)}).Debug("Creating Red25519 public key")

	if len(data) != PublicKeySize {
		return nil, ErrInvalidPublicKeySize
	}
	p := decodePoint(data)
	if p == nil {
		return nil, oops.Wrapf(ErrInvalidPublicKeySize, "public key is not a valid encoded Edwards point")
	}
	key := make(Red25519PublicKey, PublicKeySize)
	copy(key, data)
	return key, nil
}

// Bytes returns the 32-byte encoded point.
func (k Red25519PublicKey) Bytes() []byte {
	return k
}

// Len returns the length in bytes (32 for a valid key).
func (k Red25519PublicKey) Len() int {
	return len(k)
}

// NewVerifier returns a verifier that checks Red25519 signatures against this
// public key using cofactor (mult-by-8) equation checking, per red25519.md
// §RedDSA functions VERIFY.
func (k Red25519PublicKey) NewVerifier() (types.Verifier, error) {
	if len(k) != PublicKeySize {
		return nil, ErrInvalidPublicKeySize
	}
	p := decodePoint(k)
	if p == nil {
		return nil, oops.Wrapf(ErrInvalidPublicKeySize, "public key is not a valid encoded Edwards point")
	}
	return &Red25519Verifier{k: k}, nil
}

// point decodes the public key to an edwards25519.Point.
func (k Red25519PublicKey) point() *edwards25519.Point {
	return decodePoint(k)
}
