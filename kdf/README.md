# kdf
--
    import "github.com/go-i2p/crypto/kdf"

![kdf.svg](kdf.svg)

Package kdf derives the keys that I2P needs from shared secrets.

# What this package does

In I2P, two routers first agree on one shared secret (for example, through an
X25519 key exchange). From that single secret the protocol needs many different
keys: one for a tunnel, one for message encryption, one for session tags, and so
on. This package derives those keys in a consistent way.

[StandardHKDF] is the canonical one-shot RFC 5869 HKDF-SHA256 wrapper used
across the crypto layer. The I2P ECIES spec defines its HKDF as HKDF(salt, ikm,
info, n) with a 32-byte salt, so callers pass the arguments in that order:

    keydata, err := kdf.StandardHKDF(salt, ikm, []byte("SymmetricRatchet"), 64)

The spec-mandated info strings ("KDFDHRatchetStep", "TagAndKeyGenKeys",
"STInitialization", "SessionTagKeyGen", "SymmetricRatchet", "XDHRatchetTagSet",
"SessionReplyTags", "AttachPayloadKDF", ...) are supplied by the callers that
implement those protocols; see crypto/ratchet and go-noise.

Destination blinding has its own conformant KDF, [DeriveBlindingFactorI2P], in
blinding.go.

# Security considerations

    - Generate root secrets from a cryptographically secure random source.
    - Pass the spec's exact salt/ikm/info values; do not invent replacements,
      or the result will not interoperate with other I2P implementations.
    - Keep each derived key unique to its purpose and context.

## Usage

```go
const (
	// SigTypeEdDSASha512Ed25519 is the standard Ed25519 signing type (code 7).
	SigTypeEdDSASha512Ed25519 uint16 = 7
	// SigTypeRedDSASha512Ed25519 is the blinded RedDSA type (code 11). Blinding
	// always produces a RedDSA alpha, so this is the sigtype-out value.
	SigTypeRedDSASha512Ed25519 uint16 = 11
)
```
SigType codes used by the I2P blinding KDF salt (see net.i2p.crypto.SigType).

#### func  DeriveBlindingFactorI2P

```go
func DeriveBlindingFactorI2P(signingPubKey []byte, secret string, sigType uint16, t time.Time) ([32]byte, error)
```
DeriveBlindingFactorI2P derives the I2P destination-blinding factor (alpha)
exactly as specified by the I2P reference implementation
(net.i2p.crypto.Blinding.generateAlpha), so the result interoperates with Java
I2P and other conforming routers.

The derivation is:

    salt = SHA256("I2PGenerateAlpha" || spk || sigtypeIn(2, BE) || 0x000b)
    ikm  = yyyyMMdd(GMT) || secretUTF8      // secret may be empty
    out  = HKDF-SHA256(salt, ikm, "i2pblinding1", 64)
    alpha = reduce(out)                     // 64-byte LE integer mod L, 32-byte LE

Parameters:

    - signingPubKey: the destination's 32-byte signing public key (spk). It is a
      mandatory input: the alpha is bound to a specific destination.
    - secret: optional UTF-8 secret mixed into the IKM (may be empty).
    - sigType: the destination's signing type code, SigTypeEdDSASha512Ed25519 (7)
      or SigTypeRedDSASha512Ed25519 (11).
    - t: the time whose GMT yyyyMMdd value is used as the rotation period.

Returns the 32-byte canonical little-endian alpha scalar.

Spec: I2P Proposal 123 (Encrypted LeaseSet) / net.i2p.crypto.Blinding.

#### func  StandardHKDF

```go
func StandardHKDF(salt, ikm, info []byte, length int) ([]byte, error)
```
StandardHKDF performs a one-shot RFC 5869 HKDF-SHA256 key derivation. This is
the canonical implementation of raw HKDF extract-and-expand in the crypto layer,
replacing ad-hoc inline implementations found in higher-level packages (e.g.,
noise handshakes, NTCP2).

Parameters:

    - salt: Optional salt value (can be nil; HKDF will use a zero-filled salt)
    - ikm: Input key material (must not be empty)
    - info: Optional context/application-specific info (can be nil)
    - length: Desired output length in bytes (must be > 0; max 255*32 per RFC 5869)

Returns:

    - []byte: Derived key material of the requested length
    - error: Any error during derivation

Example usage:

    derived, err := kdf.StandardHKDF(salt, sharedSecret, []byte("NTCP2-KDF"), 32)
    if err != nil {
        return err
    }



kdf 

github.com/go-i2p/crypto/kdf

[go-i2p template file](/template.md)
