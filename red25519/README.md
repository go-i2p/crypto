# red25519
--
    import "github.com/go-i2p/crypto/red25519"

Package red25519 provides Red25519 (RedDSA) digital signature functionality for
I2P cryptographic operations. This package wraps
[github.com/go-i2p/red25519](https://github.com/go-i2p/red25519) to implement
the `types.SigningPublicKey`, `types.SigningPrivateKey`, `types.Signer`, and
`types.Verifier` interfaces used throughout the go-i2p/crypto library.

Red25519 extends standard Ed25519 with key blinding: a 32-byte scalar blinding
factor is multiplied into both the private and public key, producing a new
keypair that is unlinkable to the original yet fully functional for signing
and verification. This is used in the I2P network for destination blinding
(encrypted leasesets, etc.).

## Ed25519 vs Red25519

| Property          | Ed25519 (PureEdDSA)        | Red25519 (RedDSA)               |
|-------------------|----------------------------|---------------------------------|
| Private key       | 64-byte seed+pubkey        | 64-byte seed+pubkey             |
| Public key        | 32-byte point              | 32-byte point                   |
| Signature         | 64 bytes (deterministic)   | 64 bytes (deterministic)        |
| Ed25519 interop   | ✅ Yes                     | ✅ Yes (unblinded)              |
| Key blinding      | ❌ No                      | ✅ Yes                          |
| Small-order keys  | Accepted                   | Rejected (stricter)             |
| Use case          | Standard I2P signatures    | Blinded/re-randomizable sigs    |

## Usage

```go
// Generate a key pair
pubKey, privKey, err := red25519.GenerateRed25519KeyPair()
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

#### type Red25519PublicKey

```go
type Red25519PublicKey upstream.PublicKey
```

Red25519PublicKey represents a Red25519 public key as a 32-byte compressed
Edwards point on the Ed25519 curve.

#### type Red25519PrivateKey

```go
type Red25519PrivateKey upstream.PrivateKey
```

Red25519PrivateKey represents a Red25519 private key as a 64-byte key
(seed + public key), compatible with crypto/ed25519 layout.

#### type Red25519Signer

```go
type Red25519Signer struct{}
```

Red25519Signer provides digital signature creation using the Red25519 (RedDSA)
Schnorr signature scheme over the Ed25519 curve.

#### type Red25519Verifier

```go
type Red25519Verifier struct{}
```

Red25519Verifier provides digital signature verification using the Red25519
(RedDSA) Schnorr signature scheme over the Ed25519 curve.

## Functions

#### func GenerateRed25519Key

```go
func GenerateRed25519Key() (types.SigningPrivateKey, error)
```

GenerateRed25519Key generates a new Red25519 private key.

#### func GenerateRed25519KeyPair

```go
func GenerateRed25519KeyPair() (*Red25519PublicKey, *Red25519PrivateKey, error)
```

GenerateRed25519KeyPair generates a new Red25519 key pair. This is the
recommended API.

#### func NewRed25519PublicKey

```go
func NewRed25519PublicKey(data []byte) (Red25519PublicKey, error)
```

NewRed25519PublicKey creates a validated Red25519 public key from bytes.

#### func NewRed25519PrivateKey

```go
func NewRed25519PrivateKey(data []byte) (Red25519PrivateKey, error)
```

NewRed25519PrivateKey creates a validated Red25519 private key from bytes.
