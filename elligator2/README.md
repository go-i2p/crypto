# elligator2
--
    import "github.com/go-i2p/crypto/elligator2"

![elligator2.svg](elligator2.svg)

Package elligator2 implements Elligator2 encoding for Curve25519 public keys.

Elligator2 encoding makes Curve25519 ephemeral public keys indistinguishable
from random data, preventing traffic analysis attacks. This is used in protocols
like I2P's ECIES-X25519-AEAD-Ratchet for New Session messages.

Specification: https://elligator.cr.yp.to/elligator-20130828.pdf

Key properties:

    - Encodes Curve25519 public keys as 32 random-looking bytes
    - Approximately 50% of Curve25519 private keys produce suitable public keys
    - Constant-time operations to prevent timing attacks
    - Bijective mapping between representatives and curve points

This implementation is based on the reference implementation by Adam Langley and
the Tor Project's implementation.

## Usage

```go
const (
	// RepresentativeSize is the size of an Elligator2 representative in bytes
	RepresentativeSize = 32

	// PublicKeySize is the size of a Curve25519 public key in bytes
	PublicKeySize = 32

	// PrivateKeySize is the size of a Curve25519 private key in bytes
	PrivateKeySize = 32
)
```

```go
var (
	// ErrNotRepresentable indicates the public key cannot be Elligator2-encoded
	ErrNotRepresentable = oops.Errorf("public key is not Elligator2-representable")

	// ErrInvalidSize indicates an input has incorrect size
	ErrInvalidSize = oops.Errorf("invalid input size for Elligator2 operation")
)
```

#### func  Decode

```go
func Decode(representative []byte) ([]byte, error)
```
Decode converts an Elligator2 representative back to a Curve25519 public key.
This operation always succeeds for valid 32-byte input.

The function masks out the 2 random MSB bits before decoding.

#### func  Encode

```go
func Encode(publicKey []byte) ([]byte, error)
```
Encode converts a Curve25519 public key to an Elligator2 representative. The
representative is indistinguishable from random data.

Returns ErrNotRepresentable if the public key cannot be encoded. Approximately
50% of Curve25519 public keys are representable.

The encoding adds 2 random bits to the MSB for full 256-bit randomness, making
the output statistically indistinguishable from random bytes.

#### func  GenerateKeyPair

```go
func GenerateKeyPair() ([]byte, []byte, error)
```
GenerateKeyPair generates a Curve25519 key pair with an Elligator2-representable
public key.

This function repeatedly generates key pairs until finding one whose public key
can be encoded. On average, this requires 2 attempts.

Returns (publicKey, privateKey, error).

#### func  IsRepresentable

```go
func IsRepresentable(publicKey []byte) bool
```
IsRepresentable checks if a Curve25519 public key can be Elligator2-encoded.



elligator2 

github.com/go-i2p/crypto/elligator2

[go-i2p template file](/template.md)
