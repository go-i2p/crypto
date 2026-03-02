package red25519

import (
	"crypto/rand"
	"io"

	upstream "github.com/go-i2p/red25519"
	"github.com/samber/oops"
)

// BlindPublicKey derives a blinded public key by multiplying the public key
// point A by the blinding factor scalar b: A' = b · A.
// The result is unlinkable to the original public key without knowledge
// of the blinding factor.
func BlindPublicKey(pub Red25519PublicKey, blind upstream.BlindingFactor) (Red25519PublicKey, error) {
	blindedPub, err := upstream.BlindPublicKey(upstream.PublicKey(pub), blind)
	if err != nil {
		return nil, oops.Errorf("failed to blind public key: %w", err)
	}
	return Red25519PublicKey(blindedPub), nil
}

// BlindPrivateKey derives a blinded private key by multiplying the private
// scalar a by the blinding factor b: a' = a · b mod ℓ.
// The resulting key can be used to sign messages that are verifiable against
// the corresponding blinded public key.
func BlindPrivateKey(priv Red25519PrivateKey, blind upstream.BlindingFactor) (Red25519PrivateKey, error) {
	blindedPriv, err := upstream.BlindPrivateKey(upstream.PrivateKey(priv), blind)
	if err != nil {
		return nil, oops.Errorf("failed to blind private key: %w", err)
	}
	return Red25519PrivateKey(blindedPriv), nil
}

// GenerateBlindingFactor generates a random blinding factor using entropy
// from the provided reader. If rand is nil, crypto/rand.Reader will be used.
func GenerateBlindingFactor(r io.Reader) (upstream.BlindingFactor, error) {
	if r == nil {
		r = rand.Reader
	}
	return upstream.GenerateBlindingFactor(r)
}

// ComposeBlindingFactors computes the scalar product of two blinding factors:
// result = bf1 · bf2 mod ℓ. Sequential blinding with bf1 then bf2 produces
// the same blinded public key as single blinding with the composed factor.
func ComposeBlindingFactors(bf1, bf2 upstream.BlindingFactor) (upstream.BlindingFactor, error) {
	return upstream.ComposeBlindingFactors(bf1, bf2)
}

// NewKeyFromSeed calculates a private key from a 32-byte seed.
// This is provided for interoperability with RFC 8032.
func NewKeyFromSeed(seed []byte) Red25519PrivateKey {
	return Red25519PrivateKey(upstream.NewKeyFromSeed(seed))
}
