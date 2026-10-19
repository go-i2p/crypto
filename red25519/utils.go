package red25519

import (
	"crypto/rand"
	"io"

	"filippo.io/edwards25519"
	"github.com/samber/oops"
)

// This file exposes the Red25519 re-randomization (blinding) and Ed25519
// conversion operations defined in red25519.md §RedDSA functions and
// §Conversion functions, and used by encryptedleaseset.md §Blinding Calculations.
//
// Blinding here is ADDITIVE, the one scheme the I2P specs define:
//
//	A' = RANDOMIZE_PUBLIC(vk, alpha) = vk + [alpha] B
//	a' = RANDOMIZE_PRIVATE(sk, alpha) = (sk + alpha) mod L
//
// The spec requires the invariant
//
//	RANDOMIZE_PUBLIC(vk, alpha) == DERIVE_PUBLIC(RANDOMIZE_PRIVATE(sk, alpha))
//
// which holds only for the additive group law. Multiplicative blinding
// (A' = [b]A, a' = a*b mod l) satisfies a different invariant and yields a
// different key for the same factor, so blinding a key pair with two different
// schemes produces signatures that do not verify. The previous implementation
// delegated to an upstream module that used the multiplicative form; it is
// replaced here with the spec's additive form so this package agrees with
// [github.com/go-i2p/crypto/ed25519] blinding for the same alpha.

// BlindingFactor is the secret scalar alpha used to re-randomize a key pair. It
// is a 32-byte little-endian scalar mod L, the same encoding as a private key.
type BlindingFactor [ScalarSize]byte

// BlindPublicKey computes A' = vk + [alpha] B (RANDOMIZE_PUBLIC).
//
// The result is checked to be a valid encoded point. The input public key must
// decode; a nil/invalid point is rejected.
func BlindPublicKey(pub Red25519PublicKey, blind BlindingFactor) (Red25519PublicKey, error) {
	vk := pub.point()
	if vk == nil {
		return nil, oops.Wrapf(ErrInvalidPublicKeySize, "public key is not a valid encoded Edwards point")
	}
	// encryptedleaseset.md §Goals requires "Blinded public keys must be on the
	// Ed25519 curve and prime-order subgroup". [alpha]B is always in the
	// prime-order subgroup, so a small-order input point would yield a blinded key
	// carrying the same torsion component. Point.SetBytes accepts torsion points,
	// so this must be checked explicitly.
	if !isInPrimeOrderSubgroup(vk) {
		return nil, ErrSmallOrderPoint
	}
	alpha, err := decodeBlindingFactor(blind)
	if err != nil {
		return nil, err
	}
	out := randomizePublic(vk, alpha)
	return Red25519PublicKey(encodePoint(out)), nil
}

// BlindPrivateKey computes a' = (a + alpha) mod L (RANDOMIZE_PRIVATE).
//
// The private key scalar is reduced mod L first, so both a clamped representative
// (from [ConvertEd25519PrivateKey]) and a canonical one are accepted. The result
// is a canonical scalar mod L.
func BlindPrivateKey(priv Red25519PrivateKey, blind BlindingFactor) (Red25519PrivateKey, error) {
	a, err := priv.scalar()
	if err != nil {
		return nil, err
	}
	alpha, err := decodeBlindingFactor(blind)
	if err != nil {
		return nil, err
	}
	out := randomizePrivate(a, alpha)
	return Red25519PrivateKey(encodeScalarLE(out)), nil
}

// GenerateBlindingFactor produces a random alpha via GENERATE_RANDOM: "s = 64
// random bytes; return s mod L". A nil reader selects crypto/rand.
func GenerateBlindingFactor(r io.Reader) (BlindingFactor, error) {
	if r == nil {
		r = rand.Reader
	}
	s, err := generateRandom(r)
	if err != nil {
		return BlindingFactor{}, oops.Wrapf(err, "GENERATE_RANDOM failed")
	}
	var bf BlindingFactor
	copy(bf[:], encodeScalarLE(s))
	return bf, nil
}

// decodeBlindingFactor decodes a BlindingFactor, rejecting the zero scalar.
//
// alpha = 0 is a no-op that leaves the key unchanged and thus leaks the original
// Destination; encryptedleaseset.md §Security implies a "biased alpha" is
// dangerous ("information about the key is leaked each time a biased alpha is
// chosen, because additive re-randomization behaves like a one-time pad"). The
// zero value is the most biased alpha possible, so it is refused.
func decodeBlindingFactor(bf BlindingFactor) (*edwards25519.Scalar, error) {
	if isAllZero(bf[:]) {
		return nil, oops.Errorf("blinding factor must not be zero")
	}
	return reduceScalarModL(bf[:])
}

// ConvertEd25519PrivateKey runs CONVERT_ED25519_PRIVATE(privkey): the Red25519
// private key corresponding to an Ed25519 private key, so an existing Ed25519
// Destination can be re-randomized.
//
//	s = SHA-512(privkey)[0..32]
//	s[0] = s[0] & 248
//	s[31] = (s[31] & 63) | 64
//	return s
//
// privkey may be a 32-byte Ed25519 seed or Go's 64-byte expanded key. The result
// is the clamped scalar, which is >= L; [NewRed25519PrivateKey] accepts it and
// reduces mod L for arithmetic. See red25519.md §Conversion functions.
func ConvertEd25519PrivateKey(ed25519PrivKey []byte) (Red25519PrivateKey, error) {
	s, err := convertEd25519Private(ed25519PrivKey)
	if err != nil {
		return nil, oops.Wrapf(ErrInvalidPrivateKeySize, "CONVERT_ED25519_PRIVATE: %v", err)
	}
	return Red25519PrivateKey(s[:]), nil
}

// ConvertEd25519PublicKey runs CONVERT_ED25519_PUBLIC(pubkey) := pubkey. The
// encoding is shared with Ed25519, so the bytes pass through; the key is still
// validated as a decodable point.
func ConvertEd25519PublicKey(ed25519PubKey []byte) (Red25519PublicKey, error) {
	p := decodePoint(ed25519PubKey)
	if p == nil {
		return nil, oops.Wrapf(ErrInvalidPublicKeySize, "CONVERT_ED25519_PUBLIC: not a valid encoded Edwards point")
	}
	out := make(Red25519PublicKey, PublicKeySize)
	copy(out, ed25519PubKey)
	return out, nil
}
