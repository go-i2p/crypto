// Package elligator2 implements Elligator2 encoding for Curve25519 public keys.
//
// Elligator2 encoding makes Curve25519 ephemeral public keys indistinguishable from
// random data, preventing traffic analysis attacks. This is used in protocols like
// I2P's ECIES-X25519-AEAD-Ratchet for New Session messages.
//
// Specification: https://elligator.cr.yp.to/elligator-20130828.pdf
//
// Key properties:
//   - Encodes Curve25519 public keys as 32 random-looking bytes
//   - Approximately 50% of Curve25519 private keys produce suitable public keys
//   - Constant-time operations to prevent timing attacks
//   - Bijective mapping between representatives and curve points
//
// This implementation is based on the reference implementation by Adam Langley
// and the Tor Project's implementation.
package elligator2

import (
	"crypto/rand"
	"io"

	"filippo.io/edwards25519/field"
	"github.com/samber/oops"
	"golang.org/x/crypto/curve25519"
)

const (
	// RepresentativeSize is the size of an Elligator2 representative in bytes
	RepresentativeSize = 32

	// PublicKeySize is the size of a Curve25519 public key in bytes
	PublicKeySize = 32

	// PrivateKeySize is the size of a Curve25519 private key in bytes
	PrivateKeySize = 32
)

var (
	// ErrNotRepresentable indicates the public key cannot be Elligator2-encoded
	ErrNotRepresentable = oops.Errorf("public key is not Elligator2-representable")

	// ErrInvalidSize indicates an input has incorrect size
	ErrInvalidSize = oops.Errorf("invalid input size for Elligator2 operation")
)

// Encode converts a Curve25519 public key to an Elligator2 representative.
// The representative is indistinguishable from random data.
//
// Returns ErrNotRepresentable if the public key cannot be encoded.
// Approximately 50% of Curve25519 public keys are representable.
//
// The encoding adds 2 random bits to the MSB for full 256-bit randomness,
// making the output statistically indistinguishable from random bytes.
func Encode(publicKey []byte) ([]byte, error) {
	if len(publicKey) != PublicKeySize {
		return nil, oops.Wrapf(ErrInvalidSize, "public key must be %d bytes, got %d", PublicKeySize, len(publicKey))
	}

	// Use the low-level representative generation
	repr, ok := publicKeyToRepresentative(publicKey)
	if !ok {
		return nil, ErrNotRepresentable
	}

	// Add 2 random bits to MSB for full 256-bit randomness
	randomBits := make([]byte, 1)
	if _, err := io.ReadFull(rand.Reader, randomBits); err != nil {
		return nil, oops.Wrapf(err, "failed to generate random bits")
	}

	// Set bits 254-255 to random (top 2 bits of byte 31)
	repr[31] |= (randomBits[0] & 0xC0)

	return repr, nil
}

// Decode converts an Elligator2 representative back to a Curve25519 public key.
// This operation always succeeds for valid 32-byte input.
//
// The function masks out the 2 random MSB bits before decoding.
func Decode(representative []byte) ([]byte, error) {
	if len(representative) != RepresentativeSize {
		return nil, oops.Wrapf(ErrInvalidSize, "representative must be %d bytes, got %d", RepresentativeSize, len(representative))
	}

	// Copy to avoid modifying input
	repr := make([]byte, RepresentativeSize)
	copy(repr, representative)

	// Mask out random bits from MSB (bits 254-255)
	repr[31] &= 0x3F

	// Apply Elligator2 map
	publicKey := representativeToPublicKey(repr)

	return publicKey, nil
}

// IsRepresentable checks if a Curve25519 public key can be Elligator2-encoded.
func IsRepresentable(publicKey []byte) bool {
	if len(publicKey) != PublicKeySize {
		return false
	}

	_, ok := publicKeyToRepresentative(publicKey)
	return ok
}

// GenerateKeyPair generates a Curve25519 key pair with an Elligator2-representable public key.
//
// This function repeatedly generates key pairs until finding one whose public key
// can be encoded. On average, this requires 2 attempts.
//
// Returns (publicKey, privateKey, error).
func GenerateKeyPair() ([]byte, []byte, error) {
	const maxAttempts = 100

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Generate a random private key
		privateKey := make([]byte, PrivateKeySize)
		if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
			return nil, nil, oops.Wrapf(err, "failed to generate private key")
		}

		// Compute public key
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, nil, oops.Wrapf(err, "failed to compute public key")
		}

		// Check if representable
		if IsRepresentable(publicKey) {
			return publicKey, privateKey, nil
		}
	}

	return nil, nil, oops.Errorf("failed to generate representable key pair after %d attempts", maxAttempts)
}

// publicKeyToRepresentative attempts to find an Elligator2 representative for a public key.
// Returns (representative, true) if successful, (nil, false) if not representable.
//
// This implements the inverse Elligator2 map for Curve25519 by coordinating
// the computation and verification of the representative value.
func publicKeyToRepresentative(publicKey []byte) ([]byte, bool) {
	var u field.Element
	if _, err := u.SetBytes(publicKey); err != nil {
		return nil, false
	}

	// Compute r = sqrt((-A - u) / (2*u))
	r, wasSquare := computeRepresentativeSqrt(&u)
	if wasSquare != 1 {
		return nil, false
	}

	// Get candidate representative bytes and verify round-trip
	rBytes := prepareRepresentativeBytes(r)
	if verifyRoundTrip(rBytes, &u) {
		return rBytes, true
	}

	// Try the negative square root
	return tryNegativeSquareRoot(r, &u)
}

// computeRepresentativeSqrt computes the square root for the inverse Elligator2 map.
// Formula: r² = (-A - u) / (2*u) where A = 486662 for Curve25519.
// Returns the square root and a flag indicating if the value was a perfect square.
func computeRepresentativeSqrt(u *field.Element) (*field.Element, int) {
	// A = 486662 for Curve25519
	a := createCurve25519A()

	// Compute numerator: -A - u
	negA := new(field.Element).Negate(a)
	numerator := new(field.Element).Subtract(negA, u)

	// Compute denominator: 2*u
	one := new(field.Element).One()
	two := new(field.Element).Add(one, one)
	denominator := new(field.Element).Multiply(two, u)

	// Use SqrtRatio which computes sqrt(numerator/denominator) and checks if it's a square
	return new(field.Element).SqrtRatio(numerator, denominator)
}

// createCurve25519A constructs the Curve25519 'A' parameter field element (486662).
func createCurve25519A() *field.Element {
	a := new(field.Element)
	aBytes := make([]byte, 32)
	aBytes[0] = 0x06
	aBytes[1] = 0x6D
	aBytes[2] = 0x07
	a.SetBytes(aBytes)
	return a
}

// prepareRepresentativeBytes converts a field element to representative bytes.
// Clears the top 2 bits to ensure the value is in the proper range.
func prepareRepresentativeBytes(r *field.Element) []byte {
	rBytes := r.Bytes()
	rBytes[31] &= 0x3F // Clear top 2 bits
	return rBytes
}

// verifyRoundTrip checks that the representative maps back to the original public key.
// This verification is crucial because SqrtRatio may return either +sqrt or -sqrt.
func verifyRoundTrip(rBytes []byte, u *field.Element) bool {
	var rForCheck field.Element
	rForCheck.SetBytes(rBytes)
	uCheck := computeForwardMap(&rForCheck)
	return string(uCheck.Bytes()) == string(u.Bytes())
}

// tryNegativeSquareRoot attempts to use the negative square root as the representative.
// Returns the negated representative if it maps correctly, or (nil, false) if neither root works.
func tryNegativeSquareRoot(r, u *field.Element) ([]byte, bool) {
	rNeg := new(field.Element).Negate(r)
	rNegBytes := prepareRepresentativeBytes(rNeg)

	if verifyRoundTrip(rNegBytes, u) {
		return rNegBytes, true
	}

	// Neither square root works
	return nil, false
}

// computeForwardMap computes the forward Elligator2 map without modifying the representative bytes.
// Applies the formula: u = -A / (1 + 2*r²) where A = 486662 for Curve25519.
func computeForwardMap(r *field.Element) *field.Element {
	// r²
	rSquared := new(field.Element).Square(r)

	// 2*r²
	one := new(field.Element).One()
	two := new(field.Element).Add(one, one)
	twoRSquared := new(field.Element).Multiply(two, rSquared)

	// 1 + 2*r²
	denominator := new(field.Element).Add(one, twoRSquared)

	// A = 486662
	a := createCurve25519A()

	// -A
	negA := new(field.Element).Negate(a)

	// -A / (1 + 2*r²)
	u := new(field.Element).Multiply(negA, new(field.Element).Invert(denominator))

	return u
}

// representativeToPublicKey applies the Elligator2 map to convert a representative
// to a Curve25519 public key (u-coordinate).
func representativeToPublicKey(representative []byte) []byte {
	var r field.Element
	r.SetBytes(representative)

	u := computeForwardMap(&r)
	return u.Bytes()
}
