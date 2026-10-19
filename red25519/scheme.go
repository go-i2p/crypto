package red25519

// The Red25519 signature scheme.
//
// This file implements the scheme specified at
// https://i2p.net/en/docs/specs/red25519/ ("Red25519 Signature Scheme",
// Proposal 123 / sig type 11), an instantiation of RedDSA over Ed25519 that
// supports additive key re-randomization. Blinding is what lets an encrypted
// LeaseSet2 be authenticated by a floodfill without revealing the Destination
// it belongs to: "Proposal 123 achieves this by blinding the signing keys of
// Destinations."
//
// Everything here is implemented directly on filippo.io/edwards25519 rather than
// by delegating to an Ed25519 implementation, because Red25519 differs from
// Ed25519 in five ways that all change the bytes on the wire:
//
//  1. H(x) := SHA-512("I2P_Red25519H(x)" || x) - a domain separator Ed25519 has
//     not.
//  2. Messages are length-prefixed, len_u16(M) || M, little-endian, because
//     "SHA-512 does not satisfy [length-extension security] on its own".
//  3. The signing nonce r is randomized: "T = 80 random bytes; r = HStar(T,
//     vkBytes, m)", so "every Red25519 signature is different, even when signing
//     the same data with the same key". Ed25519's deterministic nonce would
//     destroy the unlinkability the scheme exists to provide.
//  4. Private keys are reduced mod L, not clamped: "Red25519 private keys are
//     generated from random numbers and then must be reduced mod L ... This is
//     not done for Red25519" [clamping].
//  5. Verification uses the cofactor: "return ((-[S] B) + R + ([c] vk)).
//     multiplyByCofactor().isIdentity()".

import (
	"crypto/rand"
	"crypto/sha512"
	"io"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/samber/oops"
)

// HStarPersonalization is the domain separator the spec prepends to every hash:
// "H(x) := SHA-512("I2P_Red25519H(x)" || x)".
const HStarPersonalization = "I2P_Red25519H(x)"

// maxMessageSize is the internal bound; the exported [MaxMessageSize] in
// constants.go documents it. The spec fixes it in §Red25519: "Messages must be no
// longer than 65534 bytes. A length of 65535 is reserved for possible future
// extensions." The length prefix is a 2-byte little-endian field, so 65535 cannot
// be represented without colliding with the reserved value.
const maxMessageSize = 65534

// nonceSizeT is the width of the random value T in "SIGN(sk, m) := T = 80 random
// bytes". 80 bytes = one full SHA-512 block plus 16 bytes, so the hash that
// produces r never repeats an input prefix.
const nonceSizeT = 80

// orderL is the Ed25519 group order, "L : The Ed25519 order 2^252 +
// 27742317777372353535851937790883648493 as in RFC-8032", as a big.Int for the
// mod-L reductions the spec's pseudocode performs.
var orderL = mustOrderL()

func mustOrderL() *big.Int {
	// L = 2^252 + 27742317777372353535851937790883648493.
	// The low term exceeds int64, so build it from its decimal string.
	l := new(big.Int).Lsh(big.NewInt(1), 252)
	add, ok := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	if !ok {
		panic("red25519: invalid Ed25519 order constant")
	}
	l.Add(l, add)
	return l
}

// hstar implements the spec's HStar:
//
//	HStar(prefix1, prefix2, m) :=
//	    h = SHA-512()
//	    h.input("I2P_Red25519H(x)")
//	    h.input(prefix1)
//	    h.input(prefix2)
//	    h.input(len(m) & 0xff)
//	    h.input((len(m) >> 8) & 0xff)
//	    h.input(m)
//	    s = h.digest()
//	    return s mod L
//
// The 64-byte digest is reduced mod L. edwards25519.Scalar.SetUniformBytes does
// exactly that reduction (on a 64-byte input) and is the constant-time path.
func hstar(prefix1, prefix2, m []byte) (*edwards25519.Scalar, error) {
	if len(m) > maxMessageSize {
		return nil, oops.Errorf("message length %d exceeds the Red25519 maximum of %d bytes", len(m), maxMessageSize)
	}
	h := sha512.New()
	h.Write([]byte(HStarPersonalization))
	h.Write(prefix1)
	h.Write(prefix2)
	// len_u16(M), little-endian, per "to be consistent with the little-endian
	// encoding of scalars and points".
	h.Write([]byte{byte(len(m)), byte(len(m) >> 8)})
	h.Write(m)
	digest := h.Sum(nil)

	s := edwards25519.NewScalar()
	if _, err := s.SetUniformBytes(digest); err != nil {
		return nil, oops.Wrapf(err, "HStar: reducing digest mod L failed")
	}
	return s, nil
}

// reduceScalarModL interprets 32 little-endian bytes as an integer and reduces it
// mod L.
//
// This is needed because a Red25519 private key converted from Ed25519 is a
// *clamped* scalar, which is always >= 2^254 and therefore >= L, while
// GENERATE_PRIVATE and RANDOMIZE_PRIVATE return values already reduced mod L.
// Both are valid 32-byte encodings, so arithmetic has to normalize rather than
// assume canonicality. Scalar.SetCanonicalBytes would reject the clamped form.
func reduceScalarModL(b []byte) (*edwards25519.Scalar, error) {
	if len(b) != ScalarSize {
		return nil, oops.Errorf("expected %d bytes for a scalar, got %d", ScalarSize, len(b))
	}
	v := new(big.Int).SetBytes(swapEndianness(b))
	v.Mod(v, orderL)
	return scalarFromBig(v)
}

// scalarFromBig converts a value already reduced mod L into a Scalar.
func scalarFromBig(v *big.Int) (*edwards25519.Scalar, error) {
	b := v.Bytes() // big-endian, no leading zeros
	if len(b) > ScalarSize {
		return nil, oops.Errorf("scalar %d bytes exceeds %d", len(b), ScalarSize)
	}
	// Left-pad to 32 big-endian bytes, then reverse to the spec's little-endian
	// scalar encoding. Placing the reversed bytes at the low end (rather than the
	// high end) is what keeps a value shorter than 32 bytes correct.
	var be [ScalarSize]byte
	copy(be[ScalarSize-len(b):], b)
	le := swapEndianness(be[:])

	s := edwards25519.NewScalar()
	if _, err := s.SetCanonicalBytes(le); err != nil {
		return nil, oops.Wrapf(err, "scalar is not canonical mod L")
	}
	return s, nil
}

// swapEndianness reverses a byte slice, converting between the spec's
// little-endian scalar encoding and big.Int's big-endian one.
func swapEndianness(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// encodeScalarLE is ENCODE_SCALAR: the little-endian 32-byte encoding of a
// scalar mod L.
func encodeScalarLE(s *edwards25519.Scalar) []byte {
	return s.Bytes() // edwards25519 already encodes little-endian
}

// decodeScalarLE is DECODE_SCALAR. It returns the scalar and whether the input
// was canonical, i.e. strictly less than L. VERIFY rejects a non-canonical S:
// "S = DECODE_SCALAR(Sbytes); if S >= L: return false".
func decodeScalarLE(b []byte) (*edwards25519.Scalar, bool) {
	if len(b) != ScalarSize {
		return nil, false
	}
	s := edwards25519.NewScalar()
	if _, err := s.SetCanonicalBytes(b); err != nil {
		return nil, false
	}
	return s, true
}

// derivePublic is DERIVE_PUBLIC(sk) := [sk] B.
func derivePublic(sk *edwards25519.Scalar) *edwards25519.Point {
	return new(edwards25519.Point).ScalarBaseMult(sk)
}

// encodePoint is ENCODE_POINT: the 32-byte compressed Edwards encoding, which
// §Encoding and decoding notes "is the same encoding as for Ed25519".
func encodePoint(p *edwards25519.Point) []byte {
	return p.Bytes()
}

// decodePoint is DECODE_POINT, returning nil for an invalid encoding.
func decodePoint(b []byte) *edwards25519.Point {
	if len(b) != PublicKeySize {
		return nil
	}
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return nil
	}
	return p
}

// isIdentity reports whether p is the neutral element of the group.
func isIdentity(p *edwards25519.Point) bool {
	return p.Equal(edwards25519.NewIdentityPoint()) == 1
}

// generatePrivate is GENERATE_PRIVATE := "s = 64 random bytes; return s mod L".
//
// Note the two deliberate differences from Ed25519 key generation: the input is
// 64 bytes reduced mod L rather than 32 bytes clamped with bitwise masking, and
// §Security implications requires the output distribution to be uniform, because
// "the distribution of Red25519 private keys generated via RANDOMIZE_PRIVATE is
// identical to the distribution of private keys generated via GENERATE_PRIVATE".
// SetUniformBytes performs the mod-L reduction in constant time.
func generatePrivate(r io.Reader) (*edwards25519.Scalar, error) {
	if r == nil {
		r = rand.Reader
	}
	buf := make([]byte, 64)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, oops.Wrapf(err, "GENERATE_PRIVATE: reading 64 random bytes failed")
	}
	s := edwards25519.NewScalar()
	if _, err := s.SetUniformBytes(buf); err != nil {
		return nil, oops.Wrapf(err, "GENERATE_PRIVATE: reducing mod L failed")
	}
	return s, nil
}

// generateRandom is GENERATE_RANDOM := "s = 64 random bytes; return s mod L" -
// the re-randomization scalar alpha. Identical construction to GENERATE_PRIVATE,
// as the spec's pseudocode shows.
func generateRandom(r io.Reader) (*edwards25519.Scalar, error) {
	return generatePrivate(r)
}

// randomizePrivate is RANDOMIZE_PRIVATE(sk, alpha) := (sk + alpha) mod L.
func randomizePrivate(sk, alpha *edwards25519.Scalar) *edwards25519.Scalar {
	return edwards25519.NewScalar().Add(sk, alpha)
}

// randomizePublic is RANDOMIZE_PUBLIC(vk, alpha) := vk + [alpha] B.
//
// This is *additive* re-randomization, the same group law as the private side,
// which is what makes the spec's required invariant hold:
// "RANDOMIZE_PUBLIC(vk, alpha) == DERIVE_PUBLIC(RANDOMIZE_PRIVATE(sk, alpha))".
// Multiplicative blinding (A' = [b]A, a' = a*b mod l) satisfies a different
// invariant and produces a different key for the same factor, so it cannot be
// mixed with this scheme.
func randomizePublic(vk *edwards25519.Point, alpha *edwards25519.Scalar) *edwards25519.Point {
	return new(edwards25519.Point).Add(vk, new(edwards25519.Point).ScalarBaseMult(alpha))
}

// convertEd25519Private is CONVERT_ED25519_PRIVATE(privkey):
//
//	s = SHA-512(privkey)[0..32]
//	s[0] = s[0] & 248
//	s[31] = (s[31] & 63) | 64
//	return s
//
// The result is the clamped scalar, which is >= L; it is returned as the 32
// bytes the spec prints, and reduced mod L only when used for arithmetic.
// privkey is the 32-byte Ed25519 seed (RFC 8032 §5.1.5 steps 1-3).
func convertEd25519Private(ed25519PrivKey []byte) ([ScalarSize]byte, error) {
	seed, err := ed25519Seed(ed25519PrivKey)
	if err != nil {
		return [ScalarSize]byte{}, err
	}
	d := sha512.Sum512(seed)
	var s [ScalarSize]byte
	copy(s[:], d[:ScalarSize])
	s[0] &= 248
	s[31] = (s[31] & 63) | 64
	return s, nil
}

// ed25519Seed accepts either a 32-byte Ed25519 seed or Go's 64-byte expanded
// private key (seed || public) and returns the 32-byte seed, which is what
// RFC 8032 and the spec's CONVERT_ED25519_PRIVATE hash.
func ed25519Seed(priv []byte) ([]byte, error) {
	switch len(priv) {
	case ScalarSize:
		return priv, nil
	case Ed25519ExpandedPrivateKeySize:
		return priv[:ScalarSize], nil
	default:
		return nil, oops.Errorf("expected an Ed25519 private key of %d (seed) or %d (expanded) bytes, got %d",
			ScalarSize, Ed25519ExpandedPrivateKeySize, len(priv))
	}
}

// sign is SIGN(sk, m):
//
//	T = 80 random bytes
//	vkBytes = ENCODE_POINT(DERIVE_PUBLIC(sk))
//	r = HStar(T, vkBytes, m)
//	R = [r] B
//	Rbytes = ENCODE_POINT(R)
//	c = HStar(Rbytes, vkBytes, m)
//	S = (r + (c * sk)) mod L
//	return Rbytes || ENCODE_SCALAR(S)
//
// sk must already be reduced mod L.
func sign(sk *edwards25519.Scalar, m, T []byte) ([]byte, error) {
	if len(T) != nonceSizeT {
		return nil, oops.Errorf("expected %d random bytes for T, got %d", nonceSizeT, len(T))
	}
	vkBytes := encodePoint(derivePublic(sk))

	r, err := hstar(T, vkBytes, m)
	if err != nil {
		return nil, oops.Wrapf(err, "SIGN: HStar(T, vk, m) failed")
	}
	Rbytes := encodePoint(derivePublic(r))

	c, err := hstar(Rbytes, vkBytes, m)
	if err != nil {
		return nil, oops.Wrapf(err, "SIGN: HStar(R, vk, m) failed")
	}
	// S = (r + (c * sk)) mod L
	S := edwards25519.NewScalar().MultiplyAdd(c, sk, r)

	sig := make([]byte, SignatureSize)
	copy(sig[:PublicKeySize], Rbytes)
	copy(sig[PublicKeySize:], encodeScalarLE(S))
	return sig, nil
}

// verify is VERIFY(vk, m, sig):
//
//	Rbytes = sig[0..32]; Sbytes = sig[32..64]
//	R = DECODE_POINT(Rbytes); if R is invalid: return false
//	S = DECODE_SCALAR(Sbytes); if S >= L: return false
//	vkBytes = ENCODE_POINT(vk)
//	c = HStar(Rbytes, vkBytes, m)
//	return ((-[S] B) + R + ([c] vk)).multiplyByCofactor().isIdentity()
//
// vk is the decoded point; pass nil to signal an undecodable public key.
func verify(vk *edwards25519.Point, m, sig []byte) (bool, error) {
	if len(sig) != SignatureSize {
		return false, nil
	}
	if vk == nil {
		return false, nil
	}
	Rbytes := sig[:PublicKeySize]
	Sbytes := sig[PublicKeySize:]

	R := decodePoint(Rbytes)
	if R == nil {
		return false, nil
	}
	S, canonical := decodeScalarLE(Sbytes)
	if !canonical {
		// "if S >= L: return false"
		return false, nil
	}

	vkBytes := encodePoint(vk)
	c, err := hstar(Rbytes, vkBytes, m)
	if err != nil {
		return false, err
	}

	// (-[S] B) + R + ([c] vk)
	negSB := new(edwards25519.Point).Negate(derivePublic(S))
	sum := new(edwards25519.Point).Add(negSB, R)
	sum.Add(sum, new(edwards25519.Point).ScalarMult(c, vk))

	// multiplyByCofactor().isIdentity(): Red25519 "uses the prime-order subgroup
	// of order L, and the cofactor h_G is 8", so verification tolerates an
	// 8-torsion component in R rather than requiring R to be in the subgroup.
	return isIdentity(new(edwards25519.Point).MultByCofactor(sum)), nil
}

// isInPrimeOrderSubgroup reports whether P lies in the order-L prime-order
// subgroup, i.e. [L]P is the identity. The full Edwards group has order 8L, so a
// point with a cofactor (order dividing 8) component fails.
//
// Used by BlindPublicKey to enforce encryptedleaseset.md §Goals ("Blinded public
// keys must be on the Ed25519 curve and prime-order subgroup"). Note this is
// deliberately NOT part of VERIFY: §RedDSA functions VERIFY multiplies the check
// equation by the cofactor precisely so that a small-order component in R is
// tolerated. The distinction is: a signing *key* must be in the subgroup, but a
// signature's R point is verified cofactor-tolerantly.
func isInPrimeOrderSubgroup(P *edwards25519.Point) bool {
	// edwards25519.Scalar is reduced mod L, so [L] cannot be a Scalar; multiply by
	// the integer L via double-and-add.
	acc := edwards25519.NewIdentityPoint()
	cur := new(edwards25519.Point).Set(P)
	for i := 0; i < orderL.BitLen(); i++ {
		if orderL.Bit(i) == 1 {
			acc.Add(acc, cur)
		}
		cur.Double(cur)
	}
	return acc.Equal(edwards25519.NewIdentityPoint()) == 1
}
