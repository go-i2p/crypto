# red25519
--
    import "github.com/go-i2p/crypto/red25519"

![red25519.svg](red25519.svg)

Package red25519 implements the Red25519 (RedDSA-SHA512-Ed25519, signature type
11) digital signature scheme for I2P.

Red25519 is a Schnorr signature scheme over Ed25519's curve that supports
additive key re-randomization ("blinding"). It exists for one purpose: encrypted
LeaseSets. An encrypted LeaseSet2 published to a floodfill must be authenticated
without revealing which Destination it belongs to, so the Destination's signing
keys are blinded; floodfills verify with the blinded key and the Destination can
prove the floodfill's copy is authentic. See
https://i2p.net/en/docs/specs/red25519/ ("Red25519 Signature Scheme") and
https://i2p.net/en/docs/specs/encryptedleaseset/ (Proposal 123). cryptography.md
§Signatures lists RedDSA-SHA512-Ed25519 "For encrypted leasesets. Supported as
of release 0.9.39".

# How it differs from Ed25519

Red25519 is NOT Ed25519 with a different name. Five things change the bytes on
the wire, all specified in red25519.md:

    - The hash is domain-separated: H(x) := SHA-512("I2P_Red25519H(x)" || x).
    - Messages are length-prefixed, len_u16(M) || M little-endian, because
      SHA-512 alone is "not secure against length extension attacks"; messages
      are capped at 65534 bytes.
    - Signing draws 80 random bytes (T) for the nonce, so "every Red25519
      signature is different, even when signing the same data with the same
      key". Deterministic signing would let an observer link two sightings of a
      blinded Destination, destroying the unlinkability the scheme provides.
    - Private keys are scalars reduced mod L, 32 bytes, never "clamped" the way
      Ed25519 derives them.
    - Verification multiplies by the cofactor (8) before the identity check.

# Blinding is additive

Both keys are re-randomized with the same scalar alpha by ADDITION:

    A' = vk + [alpha] B
    a' = (a + alpha) mod L

which is what makes the spec's required invariant hold:

    RANDOMIZE_PUBLIC(vk, alpha) == DERIVE_PUBLIC(RANDOMIZE_PRIVATE(sk, alpha))

[BlindPublicKey] and [BlindPrivateKey] implement exactly this and agree with
[github.com/go-i2p/crypto/ed25519]'s blinding for the same alpha. Do not mix the
two key operations with a multiplicative scheme (A' = [b]A, a' = a*b mod l): it
satisfies a different invariant, so blinding the private key one way and the
public key the other produces a keypair whose signatures never verify.

The blinding factor alpha comes from
[github.com/go-i2p/crypto/kdf].DeriveBlindingFactorI2P, which implements
encryptedleaseset.md GENERATE_ALPHA.

# Converting an Ed25519 Destination

Ed25519 keys may be converted one-way so an existing Destination can be blinded:
[ConvertEd25519PrivateKey] (CONVERT_ED25519_PRIVATE) and
[ConvertEd25519PublicKey] (CONVERT_ED25519_PUBLIC). red25519.md §Security
implications notes the converted key distribution is slightly weaker than
GENERATE_PRIVATE; "Users who are concerned about this security reduction should
use Red25519 as the sigtype for their Destinations instead of Ed25519."

# Interoperability

[TestRed25519SpecVectors] (in spec_vectors_test.go) checks this implementation
against all ten test vectors published in red25519.md §Test vectors, generated
by the reference implementation: the conversions, DERIVE_PUBLIC, both
re-randomization functions, the blinding invariant, and VERIFY of signatures
this code never produced.

Note: Red25519 is for signatures only - use the curve25519 package for
encryption operations.

## Usage

```go
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
```

```go
const HStarPersonalization = "I2P_Red25519H(x)"
```
HStarPersonalization is the domain separator the spec prepends to every hash:
"H(x) := SHA-512("I2P_Red25519H(x)" || x)".

```go
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
```
Error constants for Red25519 operations.

#### func  GenerateRed25519Key

```go
func GenerateRed25519Key() (types.SigningPrivateKey, error)
```
GenerateRed25519Key runs GENERATE_PRIVATE: "s = 64 random bytes; return s mod
L". The result is a uniformly random scalar mod L, which red25519.md §Security
implications requires so that re-randomized keys are "identically distributed"
to freshly generated ones.

#### func  GenerateRed25519KeyPair

```go
func GenerateRed25519KeyPair() (*Red25519PublicKey, *Red25519PrivateKey, error)
```
GenerateRed25519KeyPair generates a Red25519 key pair. This is the recommended
API, returning concrete types without interface conversions.

The private key is DERIVE_PUBLIC-consistent with the public key by construction:
public = [sk] B.

Example:

    pubKey, privKey, err := red25519.GenerateRed25519KeyPair()
    if err != nil {
    	return err
    }
    defer privKey.Zero()

#### func  GenerateRed25519KeyWith

```go
func GenerateRed25519KeyWith(r io.Reader) (types.SigningPrivateKey, error)
```
GenerateRed25519KeyWith generates a key from an explicit entropy source. A nil
reader selects crypto/rand.

#### type BlindingFactor

```go
type BlindingFactor [ScalarSize]byte
```

BlindingFactor is the secret scalar alpha used to re-randomize a key pair. It is
a 32-byte little-endian scalar mod L, the same encoding as a private key.

#### func  GenerateBlindingFactor

```go
func GenerateBlindingFactor(r io.Reader) (BlindingFactor, error)
```
GenerateBlindingFactor produces a random alpha via GENERATE_RANDOM: "s = 64
random bytes; return s mod L". A nil reader selects crypto/rand.

#### type Red25519PrivateKey

```go
type Red25519PrivateKey []byte
```

Red25519PrivateKey is a Red25519 private key: a scalar mod L encoded in 32-byte
little-endian form.

red25519.md §Encoding and decoding: "Red25519 private keys are scalars mod L,
encoded in little-endian representation", and common-structures.md
§SigningPrivateKey lists "RedDSA_SHA512_Ed25519 | 32 | 0.9.39". The length is
therefore 32, not Go's crypto/ed25519 64-byte seed||public layout, and the
scalar is reduced mod L rather than clamped: "Red25519 private keys are
generated from random numbers and then must be reduced mod L ... This is not
done for Red25519."

Two representatives are valid here: a reduced scalar (< L) from
[GenerateRed25519Key] or a blinding operation, and the clamped scalar (>= L)
produced by [ConvertEd25519PrivateKey], which the spec's test vectors print in
that form. Arithmetic reduces mod L as needed, and both derive the same public
key.

CRITICAL: Always use [NewRed25519PrivateKey], [GenerateRed25519Key] or
[ConvertEd25519PrivateKey] to create instances.

#### func  BlindPrivateKey

```go
func BlindPrivateKey(priv Red25519PrivateKey, blind BlindingFactor) (Red25519PrivateKey, error)
```
BlindPrivateKey computes a' = (a + alpha) mod L (RANDOMIZE_PRIVATE).

The private key scalar is reduced mod L first, so both a clamped representative
(from [ConvertEd25519PrivateKey]) and a canonical one are accepted. The result
is a canonical scalar mod L.

#### func  ConvertEd25519PrivateKey

```go
func ConvertEd25519PrivateKey(ed25519PrivKey []byte) (Red25519PrivateKey, error)
```
ConvertEd25519PrivateKey runs CONVERT_ED25519_PRIVATE(privkey): the Red25519
private key corresponding to an Ed25519 private key, so an existing Ed25519
Destination can be re-randomized.

    s = SHA-512(privkey)[0..32]
    s[0] = s[0] & 248
    s[31] = (s[31] & 63) | 64
    return s

privkey may be a 32-byte Ed25519 seed or Go's 64-byte expanded key. The result
is the clamped scalar, which is >= L; [NewRed25519PrivateKey] accepts it and
reduces mod L for arithmetic. See red25519.md §Conversion functions.

#### func  NewRed25519PrivateKey

```go
func NewRed25519PrivateKey(data []byte) (Red25519PrivateKey, error)
```
NewRed25519PrivateKey creates a Red25519 private key from its 32-byte
little-endian scalar encoding (common-structures.md §SigningPrivateKey:
RedDSA_SHA512_Ed25519 = 32 bytes).

The bytes are validated as a scalar encoding: 32 bytes, and either a canonical
value mod L or the clamped form produced by [ConvertEd25519PrivateKey]. A
clamped value is accepted because the spec's own test vectors carry sk in that
form; it is reduced mod L before use.

#### func (Red25519PrivateKey) Bytes

```go
func (k Red25519PrivateKey) Bytes() []byte
```
Bytes returns the 32-byte little-endian scalar encoding of the private key, the
form common-structures.md §SigningPrivateKey specifies.

#### func (Red25519PrivateKey) Generate

```go
func (k Red25519PrivateKey) Generate() (types.SigningPrivateKey, error)
```
Generate creates a new random Red25519 private key via GENERATE_PRIVATE.

#### func (Red25519PrivateKey) Len

```go
func (k Red25519PrivateKey) Len() int
```
Len returns the length of the private key in bytes (32 for a valid key).

#### func (Red25519PrivateKey) NewSigner

```go
func (k Red25519PrivateKey) NewSigner() (types.Signer, error)
```
NewSigner returns a signer that produces Red25519 signatures with this key.

#### func (*Red25519PrivateKey) NewVerifier

```go
func (k *Red25519PrivateKey) NewVerifier() (types.Verifier, error)
```
NewVerifier returns a verifier for this key's public component. It is a
convenience on the private key; the types.SigningPublicKey method lives on
Red25519PublicKey.

#### func (Red25519PrivateKey) Public

```go
func (k Red25519PrivateKey) Public() (types.SigningPublicKey, error)
```
Public returns DERIVE_PUBLIC(sk) = [sk] B, the 32-byte encoded public point.

#### func (Red25519PrivateKey) Zero

```go
func (k Red25519PrivateKey) Zero()
```
Zero securely clears the private key material from memory.

#### type Red25519PublicKey

```go
type Red25519PublicKey []byte
```

Red25519PublicKey is a Red25519 public key: a point on the Edwards form of
Curve25519, encoded as the 32-byte little-endian y-coordinate with the sign of x
in the top bit (red25519.md §Encoding and decoding: "the same encoding as for
Ed25519").

CRITICAL: Always use [NewRed25519PublicKey] to create instances.

#### func  BlindPublicKey

```go
func BlindPublicKey(pub Red25519PublicKey, blind BlindingFactor) (Red25519PublicKey, error)
```
BlindPublicKey computes A' = vk + [alpha] B (RANDOMIZE_PUBLIC).

The result is checked to be a valid encoded point. The input public key must
decode; a nil/invalid point is rejected.

#### func  ConvertEd25519PublicKey

```go
func ConvertEd25519PublicKey(ed25519PubKey []byte) (Red25519PublicKey, error)
```
ConvertEd25519PublicKey runs CONVERT_ED25519_PUBLIC(pubkey) := pubkey. The
encoding is shared with Ed25519, so the bytes pass through; the key is still
validated as a decodable point.

#### func  NewRed25519PublicKey

```go
func NewRed25519PublicKey(data []byte) (Red25519PublicKey, error)
```
NewRed25519PublicKey validates and stores a 32-byte encoded Red25519 public
point.

The point must decode on the curve. It must also be in the prime-order subgroup:
encryptedleaseset.md §Goals requires "Blinded public keys must be on the Ed25519
curve and prime-order subgroup", and a small-order (cofactor) component would
let an attacker forge against a key whose public component the holder does not
know the discrete log of. The check is [8]A != identity test being the identity
only for the order-1 subgroup element combined with the requirement that A is
not a torsion point; see the note in NewVerifier for how verification itself
tolerates 8-torsion in R but not in the key.

#### func (Red25519PublicKey) Bytes

```go
func (k Red25519PublicKey) Bytes() []byte
```
Bytes returns the 32-byte encoded point.

#### func (Red25519PublicKey) Len

```go
func (k Red25519PublicKey) Len() int
```
Len returns the length in bytes (32 for a valid key).

#### func (Red25519PublicKey) NewVerifier

```go
func (k Red25519PublicKey) NewVerifier() (types.Verifier, error)
```
NewVerifier returns a verifier that checks Red25519 signatures against this
public key using cofactor (mult-by-8) equation checking, per red25519.md §RedDSA
functions VERIFY.

#### type Red25519Signer

```go
type Red25519Signer struct {
}
```

Red25519Signer produces Red25519 signatures. It is created from a
[Red25519PrivateKey] via [Red25519PrivateKey.NewSigner].

#### func (*Red25519Signer) Sign

```go
func (s *Red25519Signer) Sign(data []byte) (sig []byte, err error)
```
Sign creates a Red25519 signature over the message data.

Red25519 is a PureEdDSA-style scheme: it signs the message directly (with the
spec's length prefix applied inside HStar), it does NOT pre-hash. Passing a
pre-computed digest here signs the digest bytes as the message. This is why Sign
and SignHash are equivalent for Red25519, matching the types.Signer contract.

Every call is randomized: SIGN begins "T = 80 random bytes" and "r = HStar(T,
vkBytes, m)", so red25519.md §Sign/Verify Calculations notes "Because of the
random data, every Red25519 signature is different, even when signing the same
data with the same key." Deterministic signing would break the unlinkability
that blinded Destinations rely on (see [Red25519PrivateKey]).

Returns [ErrMessageTooLong] if len(data) exceeds [MaxMessageSize] (65534), and
[ErrInvalidPrivateKeySize] if the key is malformed.

#### func (*Red25519Signer) SignHash

```go
func (s *Red25519Signer) SignHash(h []byte) (sig []byte, err error)
```
SignHash signs h as the message. Red25519 does not pre-hash, so this is an alias
for [Red25519Signer.Sign] and the input is treated as message bytes, not a
digest.

#### type Red25519Verifier

```go
type Red25519Verifier struct {
}
```

Red25519Verifier checks Red25519 signatures against a public key.

#### func (*Red25519Verifier) Verify

```go
func (v *Red25519Verifier) Verify(data, sig []byte) error
```
Verify checks sig against the message data. Red25519 does not pre-hash, so data
is the message exactly as signed.

#### func (*Red25519Verifier) VerifyHash

```go
func (v *Red25519Verifier) VerifyHash(h, sig []byte) error
```
VerifyHash checks sig with h treated as the message bytes. Red25519 is a
PureEdDSA-style scheme and does not pre-hash, so this is equivalent to
[Red25519Verifier.Verify].



red25519 

github.com/go-i2p/crypto/red25519

[go-i2p template file](/template.md)
