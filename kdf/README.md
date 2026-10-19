# kdf
--
    import "github.com/go-i2p/crypto/kdf"

![kdf.svg](kdf.svg)

Package kdf derives the many different keys that I2P needs from a single shared
secret.

# What this package does

In I2P, two routers first agree on one shared secret (for example, through an
X25519 key exchange). From that single secret, the protocol needs many different
keys: one for tunnel encryption, one for message encryption, one for session
tags, and so on. This package derives all of those keys in a consistent way.

It uses HKDF (HMAC-based Key Derivation Function), a standard method defined in
RFC 5869, with SHA-256 as the hash. Each key is derived with a purpose-specific
"info" string so that keys for different jobs never collide.

# Usage

    // Start from a shared secret.
    kd := kdf.NewKeyDerivation(sharedSecret)

    // Derive a key for a specific purpose.
    tunnelKey, _ := kd.DeriveForPurpose(kdf.PurposeTunnelEncryption)

# Key purposes

The KeyPurpose type names the standard jobs a derived key can be used for, such
as tunnel encryption, garlic message encryption, session tags, and ratchet
chains. Using the standard purposes keeps keys consistent across the whole I2P
ecosystem.

# Security considerations

    - Generate root secrets from a cryptographically secure random source.
    - Prefer the standard key purposes so keys stay consistent.
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

```go
var (
	// ErrInvalidSecret indicates the secret is too short for secure blinding factor derivation
	ErrInvalidSecret = oops.Errorf("secret must be at least 32 bytes")

	// ErrInvalidDateFormat indicates the date string does not match YYYY-MM-DD format
	ErrInvalidDateFormat = oops.Errorf("date must be in YYYY-MM-DD format")

	// ErrInvalidDate indicates the date values are invalid (e.g., Feb 30)
	ErrInvalidDate = oops.Errorf("invalid date values")
)
```

#### func  DeriveBlindingFactor

```go
func DeriveBlindingFactor(secret []byte, date string) ([32]byte, error)
```
DeriveBlindingFactor derives a blinding factor (alpha) from a secret and date
using a non-standard HKDF construction:

    - IKM (input key material): secret (32+ bytes)
    - Salt: date in YYYY-MM-DD format as bytes
    - Info: "i2p-blinding-factor"
    - Output: 64 bytes, reduced to a canonical Ed25519 scalar (< L)

The same secret + date always produces the same alpha.

Parameters:

    - secret: Secret key material (must be at least 32 bytes, typically from private key)
    - date: Date in "YYYY-MM-DD" format (e.g., "2025-11-24")

Returns:

    - alpha: 32-byte canonical Ed25519 scalar suitable for point blinding
    - error: ErrInvalidSecret if secret is too short, ErrInvalidDateFormat or ErrInvalidDate if date is invalid

Deprecated: this is NOT the I2P destination-blinding KDF. It omits the
destination signing public key and the sig-type codes from the salt, uses the
date as the HKDF salt rather than the SHA256("I2PGenerateAlpha"||spk||...) salt,
mixes the secret in as IKM with a YYYY-MM-DD (not yyyyMMdd) prefix, and uses
info "i2p-blinding-factor" rather than "i2pblinding1". The result is
self-consistent but interoperates with no I2P implementation. Use
DeriveBlindingFactorI2P for a conformant alpha.

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

#### func  DeriveBlindingFactorWithTimestamp

```go
func DeriveBlindingFactorWithTimestamp(secret []byte, unixTimestamp int64) ([32]byte, error)
```
DeriveBlindingFactorWithTimestamp is a convenience wrapper that formats a Unix
timestamp into YYYY-MM-DD and calls DeriveBlindingFactor.

This is useful when working with Unix timestamps (e.g., from time.Now().Unix()).

Parameters:

    - secret: Secret key material (must be at least 32 bytes)
    - unixTimestamp: Unix timestamp in seconds

Returns:

    - alpha: 32-byte blinding factor
    - error: Same errors as DeriveBlindingFactor

Deprecated: like [DeriveBlindingFactor], the result interoperates with no I2P
implementation. Use [DeriveBlindingFactorI2P], which takes a time.Time directly
and derives the spec-conformant alpha.

Example:

    // Derive blinding factor for current time
    now := time.Now().Unix()
    alpha, err := kdf.DeriveBlindingFactorWithTimestamp(secret, now)

#### func  FormatDateForBlinding

```go
func FormatDateForBlinding(t time.Time) string
```
FormatDateForBlinding formats a time.Time as YYYY-MM-DD for blinding factor
derivation. This is a convenience function for consistent date formatting.

Deprecated: the YYYY-MM-DD date format is only used by the non-interoperable
[DeriveBlindingFactor]. Use [DeriveBlindingFactorI2P], which takes a time.Time
directly.

Example:

    date := kdf.FormatDateForBlinding(time.Now())
    alpha, err := kdf.DeriveBlindingFactor(secret, date)

#### func  GetCurrentBlindingDate

```go
func GetCurrentBlindingDate() string
```
GetCurrentBlindingDate returns today's date in UTC formatted for blinding. This
is equivalent to FormatDateForBlinding(time.Now().UTC()).

Deprecated: the YYYY-MM-DD date format is only used by the non-interoperable
[DeriveBlindingFactor]. Use [DeriveBlindingFactorI2P], which takes a time.Time
directly.

Example:

    today := kdf.GetCurrentBlindingDate()
    alpha, err := kdf.DeriveBlindingFactor(secret, today)

#### func  StandardHKDF

```go
func StandardHKDF(salt, ikm, info []byte, length int) ([]byte, error)
```
StandardHKDF performs a one-shot RFC 5869 HKDF-SHA256 key derivation. This is a
convenience function for callers that need a single HKDF invocation without
constructing a KeyDerivation context. It is the canonical implementation of raw
HKDF extract-and-expand in the crypto layer, replacing ad-hoc inline
implementations found in higher-level packages (e.g., noise handshakes, NTCP2).

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

#### type KeyDerivation

```go
type KeyDerivation struct {
}
```

KeyDerivation provides consistent key derivation from a root key. All derived
keys use HKDF-SHA256 with purpose-specific info strings.

# Protocol scope

KeyDerivation is the KDF for the legacy ECIES-X25519-AEAD-Ratchet protocol (see
crypto/ecies and crypto/ratchet.Session). It is NOT the KDF used by the
spec-compliant I2P Noise path (Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256), which
is implemented in go-noise/ratchet and uses StandardHKDF directly with the
spec-mandated salt/ikm/info arguments.

The two protocols are distinct and self-consistent; do not mix them. For the
spec-compliant Noise data-phase KDFs, use StandardHKDF with the exact (salt,
ikm, info) values from the I2P spec rather than these methods.

#### func  NewKeyDerivation

```go
func NewKeyDerivation(rootKey [32]byte) *KeyDerivation
```
NewKeyDerivation creates a new key derivation context from a root key. The root
key should be a high-entropy secret such as:

    - ECIES shared secret
    - Master session key
    - DH shared secret

Parameters:

    - rootKey: A 32-byte root key

Returns:

    - *KeyDerivation: The key derivation context

Example:

    // From ECIES shared secret
    kd := kdf.NewKeyDerivation(eciesSharedSecret)

    // From DH key agreement
    sharedSecret, _ := dhPrivate.SharedKey(dhPublic)
    kd := kdf.NewKeyDerivation([32]byte(sharedSecret))

#### func (*KeyDerivation) DeriveForPurpose

```go
func (kd *KeyDerivation) DeriveForPurpose(purpose KeyPurpose) ([32]byte, error)
```
DeriveForPurpose derives a single 32-byte key for a specific I2P purpose. This
uses standard info strings defined for each purpose.

Parameters:

    - purpose: The intended use of the derived key

Returns:

    - [32]byte: The derived key
    - error: Any error during derivation

Example:

    kd := kdf.NewKeyDerivation(rootKey)

    // Derive keys for different purposes
    tunnelKey, _ := kd.DeriveForPurpose(kdf.PurposeTunnelEncryption)
    garlicKey, _ := kd.DeriveForPurpose(kdf.PurposeGarlicEncryption)
    tagKey, _ := kd.DeriveForPurpose(kdf.PurposeSessionTag)

#### func (*KeyDerivation) DeriveKeys

```go
func (kd *KeyDerivation) DeriveKeys(info []byte, count int) ([][32]byte, error)
```
DeriveKeys derives multiple 32-byte keys from the same context. This is useful
when you need several related keys (e.g., encrypt + MAC + IV).

Parameters:

    - info: Context-specific info string
    - count: Number of keys to derive

Returns:

    - [][32]byte: Slice of derived keys
    - error: Any error during derivation

Example:

    // Derive 3 keys for encryption, MAC, and IV generation
    keys, _ := kd.DeriveKeys([]byte("Tunnel-Layer-42"), 3)
    encryptKey := keys[0]
    macKey := keys[1]
    ivKey := keys[2]

#### func (*KeyDerivation) DeriveSessionKeys

```go
func (kd *KeyDerivation) DeriveSessionKeys() (rootKey, symKey, tagKey [32]byte, err error)
```
DeriveSessionKeys is a convenience function that derives the standard set of
keys needed for an I2P session: ratchet root key, symmetric chain key, and tag
chain key.

This is equivalent to DeriveKeys() but with semantic naming for session
initialization.

NOTE: This uses the legacy ECIES-X25519-AEAD-Ratchet protocol's KDF with the
"ECIES-Session-KDF" info string. It is NOT the spec-compliant I2P Noise
data-phase KDF (which uses HKDF with the spec's exact salt/ikm/info values). Do
not use this for the Noise_IKelg2+hs2 path; use StandardHKDF there instead.

Deprecated: This is a legacy, non-spec-compliant KDF. Use [ratchet.Session],
which derives keys with the spec-mandated KDFs.

Returns:

    - rootKey: Key for DH ratchet initialization
    - symKey: Key for symmetric ratchet chain
    - tagKey: Key for session tag ratchet
    - error: Any error during derivation

Example:

    kd := kdf.NewKeyDerivation(eciesSharedSecret)
    rootKey, symKey, tagKey, err := kd.DeriveSessionKeys()
    if err != nil {
        return err
    }

    // Initialize session ratchets
    dhRatchet := ratchet.NewDHRatchet(rootKey, ourPriv, theirPub)
    symRatchet := ratchet.NewSymmetricRatchet(symKey)
    tagRatchet := ratchet.NewTagRatchet(tagKey)

#### func (*KeyDerivation) DeriveWithInfo

```go
func (kd *KeyDerivation) DeriveWithInfo(info string) ([32]byte, error)
```
DeriveWithInfo derives a single 32-byte key using a custom info string. Use this
when you need non-standard key derivation contexts.

Parameters:

    - info: Context-specific info string (should be unique per use case)

Returns:

    - [32]byte: The derived key
    - error: Any error during derivation

Example:

    // Derive key for custom protocol extension
    customKey, _ := kd.DeriveWithInfo("MyApp-Extension-v1")

    // Derive key with session-specific context
    sessionKey, _ := kd.DeriveWithInfo(fmt.Sprintf("Session-%s", sessionID))

#### func (*KeyDerivation) Zero

```go
func (kd *KeyDerivation) Zero()
```
Zero securely clears the root key from memory. Call this when the KeyDerivation
instance is no longer needed.

#### type KeyPurpose

```go
type KeyPurpose int
```

KeyPurpose identifies what a derived key will be used for. This ensures keys are
derived with purpose-specific context strings.

```go
const (
	// PurposeTunnelEncryption is for deriving tunnel layer encryption keys
	PurposeTunnelEncryption KeyPurpose = iota

	// PurposeGarlicEncryption is for deriving garlic message encryption keys
	PurposeGarlicEncryption

	// PurposeSessionTag is for deriving session tag generation keys
	PurposeSessionTag

	// PurposeRatchetChain is for deriving ratchet chain keys
	PurposeRatchetChain

	// PurposeIVGeneration is for deriving IV/nonce generation keys
	PurposeIVGeneration

	// PurposeMessageKey is for deriving per-message encryption keys
	PurposeMessageKey

	// PurposeHandshake is for deriving handshake-related keys
	PurposeHandshake

	// PurposeAttachPayload is for deriving keys for attached payload encryption
	// in New Session (NS) and New Session Reply (NSR) messages.
	// Java I2P compatible - uses "AttachPayloadKDF" info string.
	PurposeAttachPayload

	// PurposeEncryptedLeaseSetEncryption is used when deriving symmetric
	// encryption keys for EncryptedLeaseSet inner data.
	//
	// The encryption key is derived from:
	//   - ECDH shared secret (X25519)
	//   - EncryptedLeaseSet cookie (32 bytes)
	//   - This purpose constant
	//
	// Info string: "i2p-encrypted-leaseset-encryption"
	//
	// Spec: I2P Proposal 123 - Encrypted LeaseSet
	PurposeEncryptedLeaseSetEncryption
)
```



kdf 

github.com/go-i2p/crypto/kdf

[go-i2p template file](/template.md)
