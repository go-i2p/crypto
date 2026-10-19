# red25519
--
    import "github.com/go-i2p/crypto/red25519"

![red25519.svg](red25519.svg)

Package red25519 provides Red25519 (RedDSA) digital signature functionality for
I2P cryptographic operations.

Red25519 extends standard Ed25519 with key blinding: a 32-byte scalar blinding
factor is multiplied into both the private and public key, producing a new
keypair that is unlinkable to the original yet fully functional for signing and
verification. This is used in the I2P network for destination blinding
(encrypted leasesets, etc.).

This package wraps github.com/go-i2p/red25519 to implement the
types.SigningPublicKey, types.SigningPrivateKey, types.Signer, and
types.Verifier interfaces used throughout the go-i2p/crypto library.

The API mirrors crypto/ed25519 with additional blinding primitives:

    - Unblinded signatures are byte-identical to crypto/ed25519
    - Key blinding produces unlinkable keypairs via scalar multiplication
    - Verify rejects small-order public keys for defense against forgery

Note: Red25519 is for signatures only - use curve25519 package for encryption
operations.

## Usage

```go
const (
	// PublicKeySize is the size in bytes of a Red25519 public key (32-byte compressed point).
	PublicKeySize = upstream.PublicKeySize

	// PrivateKeySize is the size in bytes of a Red25519 private key (64-byte seed+pubkey).
	PrivateKeySize = upstream.PrivateKeySize

	// SignatureSize is the size in bytes of a Red25519 signature (R || S).
	SignatureSize = upstream.SignatureSize

	// SeedSize is the size in bytes of private key seeds.
	SeedSize = upstream.SeedSize

	// BlindedPrivateKeySize is the size in bytes of a blinded Red25519 private key
	// in the upstream extended format (blinded scalar + derived prefix + public
	// key = 32+32+32 = 96 bytes).
	BlindedPrivateKeySize = 96
)
```

```go
var (
	// ErrInvalidPublicKeySize indicates a Red25519 public key does not meet the required 32-byte size.
	ErrInvalidPublicKeySize = oops.Errorf("failed to verify: invalid red25519 public key size")

	// ErrInvalidPrivateKeySize indicates a Red25519 private key does not meet the required 64-byte size.
	ErrInvalidPrivateKeySize = oops.Errorf("invalid red25519 private key size")

	// ErrInvalidSignatureSize indicates a Red25519 signature does not meet the required 64-byte size.
	ErrInvalidSignatureSize = oops.Errorf("invalid red25519 signature size")
)
```
Error constants for Red25519 operations.

#### func  ComposeBlindingFactors

```go
func ComposeBlindingFactors(bf1, bf2 upstream.BlindingFactor) (upstream.BlindingFactor, error)
```
ComposeBlindingFactors computes the scalar product of two blinding factors:
result = bf1 · bf2 mod ℓ. Sequential blinding with bf1 then bf2 produces the
same blinded public key as single blinding with the composed factor.

#### func  GenerateBlindingFactor

```go
func GenerateBlindingFactor(r io.Reader) (upstream.BlindingFactor, error)
```
GenerateBlindingFactor generates a random blinding factor using entropy from the
provided reader. If rand is nil, crypto/rand.Reader will be used.

#### func  GenerateRed25519Key

```go
func GenerateRed25519Key() (types.SigningPrivateKey, error)
```
GenerateRed25519Key generates a new Red25519 private key. This function creates
a cryptographically secure Red25519 keypair using the system's random number
generator. The returned private key implements the SigningPrivateKey interface.

#### func  GenerateRed25519KeyPair

```go
func GenerateRed25519KeyPair() (*Red25519PublicKey, *Red25519PrivateKey, error)
```
GenerateRed25519KeyPair generates a new Red25519 key pair. This is the
recommended API for generating Red25519 keys, returning concrete types directly
without interface conversions.

Returns:

    - *Red25519PublicKey: The public key for Red25519 signature verification
    - *Red25519PrivateKey: The private key for Red25519 signing (must be zeroed after use)
    - error: Any error that occurred during key generation

Example:

    pubKey, privKey, err := red25519.GenerateRed25519KeyPair()
    if err != nil {
        return err
    }
    defer privKey.Zero()

#### type Red25519PrivateKey

```go
type Red25519PrivateKey upstream.PrivateKey
```

Red25519PrivateKey represents a Red25519 private key for signing and key
blinding operations. The key format is identical to standard Ed25519 (64 bytes:
32-byte seed + 32-byte public key), but the signing and verification use
Red25519's stricter validation (rejecting small-order keys).

CRITICAL: Always use NewRed25519PrivateKey() or GenerateRed25519KeyPair() to
create instances.

Security:

    - Private keys contain sensitive material
    - Always call Zero() when done to clear memory
    - Never log or transmit private keys

#### func  BlindPrivateKey

```go
func BlindPrivateKey(priv Red25519PrivateKey, blind upstream.BlindingFactor) (Red25519PrivateKey, error)
```
BlindPrivateKey derives a blinded private key by multiplying the private scalar
a by the blinding factor b: a' = a · b mod ℓ. The resulting key can be used to
sign messages that are verifiable against the corresponding blinded public key.

#### func  NewKeyFromSeed

```go
func NewKeyFromSeed(seed []byte) Red25519PrivateKey
```
NewKeyFromSeed calculates a private key from a 32-byte seed. This is provided
for interoperability with RFC 8032.

#### func  NewRed25519PrivateKey

```go
func NewRed25519PrivateKey(data []byte) (Red25519PrivateKey, error)
```
NewRed25519PrivateKey creates a validated Red25519 private key from bytes. This
is the REQUIRED constructor.

Parameters:

    - data: Must be exactly 64 bytes

Returns error if data length is invalid.

#### func (Red25519PrivateKey) Bytes

```go
func (k Red25519PrivateKey) Bytes() []byte
```
Bytes returns the raw byte representation of the Red25519 private key. The
returned slice contains the full 64-byte private key including the seed and the
embedded public key portion.

#### func (Red25519PrivateKey) Generate

```go
func (k Red25519PrivateKey) Generate() (types.SigningPrivateKey, error)
```
Generate creates a new random Red25519 private key. This method generates a
fresh keypair and returns it as a SigningPrivateKey interface.

#### func (Red25519PrivateKey) Len

```go
func (k Red25519PrivateKey) Len() int
```
Len returns the length of the Red25519 private key in bytes. Red25519 private
keys are always 64 bytes long.

#### func (Red25519PrivateKey) NewSigner

```go
func (k Red25519PrivateKey) NewSigner() (types.Signer, error)
```
NewSigner creates a new Red25519 signer instance for generating signatures.
Returns a signer that creates Red25519 signatures compatible with Ed25519.

#### func (*Red25519PrivateKey) NewVerifier

```go
func (k *Red25519PrivateKey) NewVerifier() (types.Verifier, error)
```
NewVerifier creates a verifier instance from this private key's public
component. This method extracts the public key and returns a Red25519 verifier
that can validate signatures created by this private key.

#### func (Red25519PrivateKey) Public

```go
func (k Red25519PrivateKey) Public() (types.SigningPublicKey, error)
```
Public extracts the Red25519 public key from this private key. Returns the
corresponding public key for Red25519 signature verification.

#### func (Red25519PrivateKey) Zero

```go
func (k Red25519PrivateKey) Zero()
```
Zero securely clears the private key material from memory. This method
overwrites all bytes of the private key with zeros to prevent potential memory
disclosure attacks. Should be called when the key is no longer needed.

#### type Red25519PublicKey

```go
type Red25519PublicKey upstream.PublicKey
```

Red25519PublicKey represents a Red25519 public key as a 32-byte compressed
Edwards point.

The key format is identical to standard Ed25519 (32 bytes), but verification is
stricter: Red25519 rejects all small-order public keys (order dividing the
cofactor 8) which would allow trivial or near-trivial signature forgery.

CRITICAL: Always use NewRed25519PublicKey() to create instances.

WRONG - Unsafe:

    var key Red25519PublicKey  // Zero value - cryptographically invalid

CORRECT - Use constructor:

    pubKey, err := red25519.NewRed25519PublicKey(pubBytes)
    if err != nil {
        return err
    }

#### func  BlindPublicKey

```go
func BlindPublicKey(pub Red25519PublicKey, blind upstream.BlindingFactor) (Red25519PublicKey, error)
```
BlindPublicKey derives a blinded public key by multiplying the public key point
A by the blinding factor scalar b: A' = b · A. The result is unlinkable to the
original public key without knowledge of the blinding factor.

#### func  NewRed25519PublicKey

```go
func NewRed25519PublicKey(data []byte) (Red25519PublicKey, error)
```
NewRed25519PublicKey creates a validated Red25519 public key from bytes. This is
the REQUIRED constructor - do not use var declarations or direct construction.

Parameters:

    - data: Must be exactly 32 bytes representing a valid compressed Edwards point

Returns error if data length is invalid.

#### func (Red25519PublicKey) Bytes

```go
func (k Red25519PublicKey) Bytes() []byte
```
Bytes returns the raw byte representation of the Red25519 public key. The
returned slice contains the 32-byte compressed Edwards point data suitable for
serialization, transmission, or storage operations.

#### func (Red25519PublicKey) Len

```go
func (k Red25519PublicKey) Len() int
```
Len returns the length of the Red25519 public key in bytes. Red25519 public keys
are always 32 bytes long.

#### func (Red25519PublicKey) NewVerifier

```go
func (k Red25519PublicKey) NewVerifier() (v types.Verifier, err error)
```
NewVerifier creates a verifier instance that can validate Red25519 signatures.
Returns a verifier configured with this public key for Red25519 signature
verification. The verifier rejects small-order public keys for defense against
forgery.

#### type Red25519Signer

```go
type Red25519Signer struct {
}
```

Red25519Signer provides digital signature creation using Red25519 (RedDSA).

Red25519 signatures are byte-identical to standard Ed25519 for unblinded keys.
The signer uses deterministic nonces and supports both normal and blinded
private keys.

#### func (*Red25519Signer) Sign

```go
func (s *Red25519Signer) Sign(data []byte) (sig []byte, err error)
```
Sign creates a Red25519 digital signature over the provided data. Returns the
64-byte signature (R || S) or an error if signing fails. Supports both normal
(64-byte) and blinded (96-byte) private keys.

#### func (*Red25519Signer) SignHash

```go
func (s *Red25519Signer) SignHash(h []byte) (sig []byte, err error)
```
SignHash creates a Red25519 signature over a pre-computed hash. For Red25519,
SignHash treats the hash as the message to sign directly.

#### type Red25519Verifier

```go
type Red25519Verifier struct {
}
```

Red25519Verifier provides digital signature verification using Red25519
(RedDSA).

Unlike standard crypto/ed25519.Verify, Red25519 verification is intentionally
stricter: it rejects all small-order public keys (points whose order divides the
cofactor 8), which would allow trivial or near-trivial signature forgery.

#### func (*Red25519Verifier) Verify

```go
func (v *Red25519Verifier) Verify(data, sig []byte) (err error)
```
Verify validates a Red25519 signature against arbitrary data. Returns an error
if verification fails.

#### func (*Red25519Verifier) VerifyHash

```go
func (v *Red25519Verifier) VerifyHash(h, sig []byte) (err error)
```
VerifyHash validates a Red25519 signature against a pre-computed hash. For
Red25519, VerifyHash treats the hash as the message, applying verification to
the provided hash bytes. Returns an error if verification fails or inputs are
invalid.



red25519 

github.com/go-i2p/crypto/red25519

[go-i2p template file](/template.md)
