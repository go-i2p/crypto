# ed25519ph
--
    import "github.com/go-i2p/crypto/ed25519ph"

Package ed25519ph provides Ed25519ph (pre-hashed) digital signature functionality.

Ed25519ph is the pre-hashed variant of Ed25519 defined in RFC 8032 §5.1.
Unlike PureEdDSA (standard Ed25519), Ed25519ph hashes the message with SHA-512
before signing, using a domain separation tag to distinguish signatures from
PureEdDSA. This makes Ed25519ph suitable for signing large messages or when
the signer cannot buffer the entire message before signing.

**IMPORTANT:** Ed25519ph signatures are NOT interchangeable with standard Ed25519
(PureEdDSA) signatures. An Ed25519ph signature cannot be verified by a PureEdDSA
verifier and vice versa, even though both use the same key format.

For standard I2P Ed25519 signatures (signature type 7: EdDSA-SHA512-Ed25519),
use the `ed25519` package instead.

## Ed25519 vs Ed25519ph

| Property          | Ed25519 (PureEdDSA)        | Ed25519ph (Pre-hashed)          |
|-------------------|----------------------------|---------------------------------|
| RFC 8032 mode     | Pure                       | Pre-hashed (§5.1)               |
| Pre-hash          | None (internal SHA-512)    | External SHA-512 + domain sep   |
| I2P sig type 7    | ✅ Yes                     | ❌ No                           |
| Interoperable     | With Java I2P, i2pd        | Only with other Ed25519ph       |
| Use case          | Standard I2P signatures    | Large messages, streaming       |

## Usage

```go
// Generate a key pair
pubKey, privKey, err := ed25519ph.GenerateEd25519phKeyPair()
if err != nil {
    return err
}
defer privKey.Zero()

// Sign data
signer, _ := privKey.NewSigner()
sig, err := signer.Sign(data)

// Verify data
verifier, _ := pubKey.NewVerifier()
err = verifier.Verify(data, sig)
```

## Types

#### type Ed25519phPublicKey

```go
type Ed25519phPublicKey []byte
```

Ed25519phPublicKey represents an Ed25519 public key for Ed25519ph signature
verification. The key format is identical to standard Ed25519 (32 bytes).

#### type Ed25519phPrivateKey

```go
type Ed25519phPrivateKey ed25519.PrivateKey
```

Ed25519phPrivateKey represents an Ed25519 private key for Ed25519ph signature
operations. The key format is identical to standard Ed25519 (64 bytes).

#### type Ed25519phSigner

```go
type Ed25519phSigner struct{}
```

Ed25519phSigner provides digital signature creation using the Ed25519ph
(pre-hashed) variant defined in RFC 8032 §5.1.

#### type Ed25519phVerifier

```go
type Ed25519phVerifier struct{}
```

Ed25519phVerifier provides digital signature verification using the Ed25519ph
(pre-hashed) variant defined in RFC 8032 §5.1.

## Functions

#### func GenerateEd25519phKey

```go
func GenerateEd25519phKey() (types.SigningPrivateKey, error)
```

GenerateEd25519phKey generates a new Ed25519 private key for Ed25519ph signatures.

#### func GenerateEd25519phKeyPair

```go
func GenerateEd25519phKeyPair() (*Ed25519phPublicKey, *Ed25519phPrivateKey, error)
```

GenerateEd25519phKeyPair generates a new Ed25519 key pair for Ed25519ph signatures.
This is the recommended API.

#### func NewEd25519phPublicKey

```go
func NewEd25519phPublicKey(data []byte) (Ed25519phPublicKey, error)
```

NewEd25519phPublicKey creates a validated Ed25519ph public key from bytes.

#### func NewEd25519phPrivateKey

```go
func NewEd25519phPrivateKey(data []byte) (Ed25519phPrivateKey, error)
```

NewEd25519phPrivateKey creates a validated Ed25519ph private key from bytes.
