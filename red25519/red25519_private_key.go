package red25519

import (
	"crypto/rand"

	"filippo.io/edwards25519"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Red25519PrivateKey is a Red25519 private key: a scalar mod L encoded in
// 32-byte little-endian form.
//
// red25519.md §Encoding and decoding: "Red25519 private keys are scalars mod L,
// encoded in little-endian representation", and common-structures.md
// §SigningPrivateKey lists "RedDSA_SHA512_Ed25519 | 32 | 0.9.39". The length is
// therefore 32, not Go's crypto/ed25519 64-byte seed||public layout, and the
// scalar is reduced mod L rather than clamped: "Red25519 private keys are
// generated from random numbers and then must be reduced mod L ... This is not
// done for Red25519."
//
// Two representatives are valid here: a reduced scalar (< L) from
// [GenerateRed25519Key] or a blinding operation, and the clamped scalar (>= L)
// produced by [ConvertEd25519PrivateKey], which the spec's test vectors print in
// that form. Arithmetic reduces mod L as needed, and both derive the same public
// key.
//
// CRITICAL: Always use [NewRed25519PrivateKey], [GenerateRed25519Key] or
// [ConvertEd25519PrivateKey] to create instances.
type Red25519PrivateKey []byte

// NewRed25519PrivateKey creates a Red25519 private key from its 32-byte
// little-endian scalar encoding (common-structures.md §SigningPrivateKey:
// RedDSA_SHA512_Ed25519 = 32 bytes).
//
// The bytes are validated as a scalar encoding: 32 bytes, and either a canonical
// value mod L or the clamped form produced by [ConvertEd25519PrivateKey]. A
// clamped value is accepted because the spec's own test vectors carry sk in that
// form; it is reduced mod L before use.
func NewRed25519PrivateKey(data []byte) (Red25519PrivateKey, error) {
	log.WithFields(logger.Fields{"pkg": "red25519", "func": "NewRed25519PrivateKey", "data_length": len(data)}).Debug("Creating Red25519 private key")

	if len(data) != PrivateKeySize {
		log.WithFields(logger.Fields{"pkg": "red25519", "func": "NewRed25519PrivateKey", "data_length": len(data)}).Error("Invalid Red25519 private key size")
		return nil, ErrInvalidPrivateKeySize
	}
	// Reject the all-zero scalar: it has no valid public key of prime order and
	// DERIVE_PUBLIC(0) is the identity, which encryptedleaseset.md §Goals forbids
	// ("Blinded public keys must be on the Ed25519 curve and prime-order
	// subgroup").
	if isAllZero(data) {
		return nil, oops.Wrapf(ErrInvalidPrivateKeySize, "Red25519 private key must not be the zero scalar")
	}
	// Validate it is a well-formed scalar representative.
	if _, err := reduceScalarModL(data); err != nil {
		return nil, oops.Wrapf(ErrInvalidPrivateKeySize, "invalid Red25519 scalar encoding: %v", err)
	}

	key := make(Red25519PrivateKey, PrivateKeySize)
	copy(key, data)
	return key, nil
}

// Bytes returns the 32-byte little-endian scalar encoding of the private key, the
// form common-structures.md §SigningPrivateKey specifies.
func (k Red25519PrivateKey) Bytes() []byte {
	return k
}

// Len returns the length of the private key in bytes (32 for a valid key).
func (k Red25519PrivateKey) Len() int {
	return len(k)
}

// Zero securely clears the private key material from memory.
func (k Red25519PrivateKey) Zero() {
	for i := range k {
		k[i] = 0
	}
}

// Public returns DERIVE_PUBLIC(sk) = [sk] B, the 32-byte encoded public point.
func (k Red25519PrivateKey) Public() (types.SigningPublicKey, error) {
	sk, err := k.scalar()
	if err != nil {
		return nil, err
	}
	return Red25519PublicKey(encodePoint(derivePublic(sk))), nil
}

// NewSigner returns a signer that produces Red25519 signatures with this key.
func (k Red25519PrivateKey) NewSigner() (types.Signer, error) {
	if len(k) != PrivateKeySize {
		return nil, ErrInvalidPrivateKeySize
	}
	// Fail early if the scalar is unusable, so NewSigner does not defer the error
	// to Sign().
	if _, err := k.scalar(); err != nil {
		return nil, err
	}
	return &Red25519Signer{k: k}, nil
}

// NewVerifier returns a verifier for this key's public component. It is a
// convenience on the private key; the types.SigningPublicKey method lives on
// Red25519PublicKey.
func (k *Red25519PrivateKey) NewVerifier() (types.Verifier, error) {
	pub, err := k.Public()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive public key")
	}
	return pub.NewVerifier()
}

// Generate creates a new random Red25519 private key via GENERATE_PRIVATE.
func (k Red25519PrivateKey) Generate() (types.SigningPrivateKey, error) {
	s, err := generatePrivate(rand.Reader)
	if err != nil {
		return nil, oops.Wrapf(err, "GENERATE_PRIVATE failed")
	}
	return Red25519PrivateKey(encodeScalarLE(s)), nil
}

// scalar decodes the private key to a reduced edwards25519.Scalar.
func (k Red25519PrivateKey) scalar() (*edwards25519.Scalar, error) {
	if len(k) != PrivateKeySize {
		return nil, ErrInvalidPrivateKeySize
	}
	s, err := reduceScalarModL(k)
	if err != nil {
		return nil, oops.Wrapf(ErrInvalidPrivateKeySize, "%v", err)
	}
	return s, nil
}

// isAllZero reports whether every byte is zero.
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
