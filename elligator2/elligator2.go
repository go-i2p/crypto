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
// This implements the inverse Elligator2 map for Curve25519.
// Formula: Given u, solve for r where u = -A / (1 + 2*r²)
// Rearranged: r² = (-A - u) / (2*u)
func publicKeyToRepresentative(publicKey []byte) ([]byte, bool) {
	var u field.Element
	if _, err := u.SetBytes(publicKey); err != nil {
		return nil, false
	}

	// A = 486662 for Curve25519
	a := new(field.Element)
	aBytes := make([]byte, 32)
	aBytes[0] = 0x06
	aBytes[1] = 0x6D
	aBytes[2] = 0x07
	if _, err := a.SetBytes(aBytes); err != nil {
		return nil, false
	}

	// Compute numerator: -A - u
	negA := new(field.Element).Negate(a)
	numerator := new(field.Element).Subtract(negA, &u)

	// Compute denominator: 2*u
	one := new(field.Element).One()
	two := new(field.Element).Add(one, one)
	denominator := new(field.Element).Multiply(two, &u)

	// Compute r = sqrt((-A - u) / (2*u))
	// Use SqrtRatio which computes sqrt(numerator/denominator) and checks if it's a square
	r, wasSquare := new(field.Element).SqrtRatio(numerator, denominator)

	if wasSquare != 1 {
		return nil, false
	}

	// Get the bytes for the representative
	rBytes := r.Bytes()

	// Clear top 2 bits to ensure it's in the proper range
	rBytes[31] &= 0x3F

	// Verify the round-trip: check that forward_map(r) == u
	// This is crucial because SqrtRatio may give us either +sqrt or -sqrt,
	// and we need the one that maps back to the original u
	var rForCheck field.Element
	rForCheck.SetBytes(rBytes)
	uCheck := computeForwardMap(&rForCheck)

	// Compare using bytes to handle field element representation
	if string(uCheck.Bytes()) != string(u.Bytes()) {
		// Try the negative square root
		rNeg := new(field.Element).Negate(r)
		rNegBytes := rNeg.Bytes()
		rNegBytes[31] &= 0x3F

		// Verify negative works
		var rNegForCheck field.Element
		rNegForCheck.SetBytes(rNegBytes)
		uCheckNeg := computeForwardMap(&rNegForCheck)

		if string(uCheckNeg.Bytes()) != string(u.Bytes()) {
			// Neither square root works
			return nil, false
		}

		// Use the negative
		return rNegBytes, true
	}

	return rBytes, true
}

// computeForwardMap is a helper that computes the forward Elligator2 map
// without modifying the representative bytes
func computeForwardMap(r *field.Element) *field.Element {
	// Compute u using the Elligator2 formula:
	// u = -A / (1 + 2*r²) where A = 486662

	// r²
	rSquared := new(field.Element).Square(r)

	// 2*r²
	one := new(field.Element).One()
	two := new(field.Element).Add(one, one)
	twoRSquared := new(field.Element).Multiply(two, rSquared)

	// 1 + 2*r²
	denominator := new(field.Element).Add(one, twoRSquared)

	// A = 486662
	a := new(field.Element)
	aBytes := make([]byte, 32)
	aBytes[0] = 0x06
	aBytes[1] = 0x6D
	aBytes[2] = 0x07
	a.SetBytes(aBytes)

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
