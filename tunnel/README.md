# tunnel
--
    import "github.com/go-i2p/crypto/tunnel"

![tunnel.svg](tunnel.svg)

Package tunnel implements the cryptography used to protect I2P tunnels.

# What this package does

I2P protects a tunnel in two different places, and the two use different
cryptography. Conflating them is the single most common mistake when reading
tunnel crypto, so this package keeps them explicitly separate:

    - Tunnel BUILDING - the TunnelBuild / Short Tunnel Build messages that
      establish a tunnel hop by hop. This is ECIES-X25519 with ChaCha20-Poly1305,
      and it is deployed: the Low-level Cryptography spec states plainly that
      "X25519 tunnel creation has replaced ElGamal tunnel creation", and
      Tunnel-Creation-ECIES is "accurate for 0.9.66", with the short-record form
      implemented since release 0.9.51. See [BuildNoiseState] and
      [EncryptBuildRequest].
    - Tunnel LAYER encryption - the symmetric encryption of every 1028-byte
      tunnel message as it flows through the established tunnel. The only layer
      encryption type defined by the specification is type 0, which is
      AES-256-CBC. See [AESEncryptor].

So ECIES is the standard for *building* tunnels, and AES is the standard for
*encrypting the traffic inside* them. Both are current; neither replaces the
other, because they operate at different layers.

# Scope: primitives, not protocol

This package holds cryptographic primitives only. The build-record functions
([EncryptBuildRequest], [DecryptBuildRequest], [DeriveBuildReplyKeys],
[EncryptOwnBuildReply], [ObfuscateOtherBuildRecord]) implement the key schedule,
the AEAD over an already-serialized record, and the reply/layer KDF chain. The
record byte layouts themselves - tunnel ID, next-router identity hash, flags,
request time, the build-options Mapping, padding, record randomization, "fake"
records, and VariableTunnelBuild message assembly - are common data structures
and protocol, and belong in github.com/go-i2p/common and the Noise packages, not
here. Callers pass in the serialized plaintext record and receive the wire
ciphertext.

# Tunnel building (ECIES-X25519)

Tunnel-Creation-ECIES builds on the Noise protocol
Noise_N_25519_ChaChaPoly_SHA256, a one-way "N" pattern: the creator (Alice) does
an ephemeral-static X25519 DH to each hop (Bob) and seals the build request
record with ChaCha20-Poly1305. The chaining key left over after that request
derives the reply key, the AES layer key, the AES IV key and, at the outbound
endpoint, the garlic reply key and tag.

Two record sizes are specified:

    - Short records (current, 0.9.51+): 154-byte request plaintext and 202-byte
      reply plaintext, both producing 218-byte encrypted records. The 218-byte
      figure is the whole wire record: for a request it is 16 (hop identity hash)
      + 32 (sender ephemeral key) + 154 (ciphertext) + 16 (Poly1305 tag); for a
      reply there is no cleartext prefix, so it is 202 + 16.
    - Long records (deprecated, 0.9.48): 464-byte request and 512-byte reply
      plaintext, both producing 528-byte encrypted records, kept that size for
      ElGamal compatibility. The spec marks this form "Deprecated, obsolete. Use
      the Short Record format".

Ephemeral keys must be unique per ECIES hop and per build record; the spec warns
that reusing them "opens an attack vector for colluding hops to confirm they are
in the same tunnel".

# Tunnel layer encryption (AES-256-CBC)

[TunnelEncryptionAES] (value 0) is the scheme I2P uses for tunnel layer
encryption: two separate AES-256 keys (one for the payload, one for the IV) in
CBC mode, over a fixed 1028-byte message. This is the only interoperable layer
option, and Tunnel-Creation-ECIES derives its keys with the KDF above rather
than transmitting them in the build record.

The layer-encryption-type field in a build request record reads "0 for AES (as
in current tunnels); 1 for future (ChaCha?)". The spec is explicit:

    "The only layer encryption currently supported is type 0, which is AES...
    Adding new layer encryption types, for example ChaCha20, is a topic for
    additional research, and is not currently a part of this specification."

[TunnelEncryptionECIES] (value 1) is an experimental local value that wraps the
ecies package's *end-to-end* one-time format. It is not the spec's layer type 1,
it is not a build record, and no deployed router accepts it as either. It also
produces variable-length output, which defeats the fixed-size tunnel layout
whose purpose is to stop intermediate hops from observing payload sizes. Do not
advertise it to a router.

Note that the local values 0 and 1 are an internal choice of this package. They
are not the same as the "crypto type" field in the I2P LeaseSet2 (LS2) records,
where ECIES-X25519 is identified by crypto type 4.

See the official specifications:

    - Tunnel-Creation-ECIES (build records, layer keys - the current tunnel
      building standard): https://i2p.net/en/docs/specs/tunnel-creation-ecies/
    - Low-level Cryptography (AES layer encryption, ElGamal legacy):
      https://i2p.net/en/docs/specs/cryptography/
    - ElGamal/AES+SessionTags (legacy end-to-end):
      https://i2p.net/en/docs/specs/elgamal-aes/
    - ECIES-X25519-AEAD-Ratchet (end-to-end, destination to destination):
      https://i2p.net/en/docs/specs/ecies/

# Message layout

A tunnel message is a fixed 1028-byte block. In the AES layer scheme the first
16 bytes are the initialization vector (IV) and the following 1008 bytes
(offsets 16..1024) are the encrypted payload; the final 4 bytes of the block are
not processed and are carried through unchanged.

## Usage

```go
const (
	// ShortBuildRequestSize is the unencrypted short BuildRequestRecord length
	// (spec: "Unencrypted size: 154 bytes").
	ShortBuildRequestSize = 154
	// ShortBuildReplySize is the unencrypted short BuildReplyRecord length
	// (spec: "Unencrypted size: 202 bytes").
	ShortBuildReplySize = 202
	// ShortBuildRecordSize is the complete on-wire short record, identical for
	// request and reply (spec: "Encrypted request and reply records will be 218
	// bytes"). A request is 16+32+154+16; a reply is 202+16.
	ShortBuildRecordSize = 218

	// ShortBuildRequestEncryptedSize is the AEAD output for a short request
	// record: the 154-byte plaintext plus the 16-byte tag, i.e. bytes 48-217 of
	// the wire record. The 16-byte identity hash and 32-byte ephemeral key that
	// precede it are cleartext framing written by the caller.
	ShortBuildRequestEncryptedSize = ShortBuildRequestSize + BuildTagSize // 170
	// ShortBuildReplyEncryptedSize is the AEAD output for a short reply record,
	// which has no cleartext prefix and so fills the whole 218-byte record.
	ShortBuildReplyEncryptedSize = ShortBuildReplySize + BuildTagSize // 218

	// LongBuildRequestSize is the deprecated long BuildRequestRecord plaintext
	// length (spec: "Unencrypted size: 464 bytes").
	LongBuildRequestSize = 464
	// LongBuildReplySize is the deprecated long BuildReplyRecord plaintext length
	// (spec: "Unencrypted size: 512 bytes").
	LongBuildReplySize = 512
	// LongBuildRecordSize is the complete on-wire long record (spec: "Encrypted
	// BuildRequestRecords are 528 bytes for both ElGamal and ECIES").
	LongBuildRecordSize = 528
	// LongBuildRequestEncryptedSize is the AEAD output for a long request record
	// (464 + 16), i.e. bytes 48-527 of the wire record.
	LongBuildRequestEncryptedSize = LongBuildRequestSize + BuildTagSize // 480
	// LongBuildReplyEncryptedSize is the AEAD output for a long reply record.
	LongBuildReplyEncryptedSize = LongBuildReplySize + BuildTagSize // 528

	// BuildNonceSize is the ChaCha20-Poly1305 nonce length used for build
	// records: "12 byte nonce, with the first 4 bytes set to zero."
	BuildNonceSize = 12
	// BuildTagSize is the Poly1305 authentication tag length.
	BuildTagSize = 16

	// MaxBuildRecords is the number of records in a tunnel build message whose
	// reply encryption uses the record number as the nonce ("n = record number
	// 0-7").
	MaxBuildRecords = 8

	// TruncatedIdentityHashSize is the 16-byte hop identity-hash prefix that
	// identifies which record belongs to which hop. The caller writes it; it is
	// not part of the AEAD input.
	TruncatedIdentityHashSize = 16
	// EphemeralPublicKeySize is the sender's X25519 ephemeral public key written
	// in cleartext ahead of the encrypted record.
	EphemeralPublicKeySize = 32
)
```

```go
var (
	ErrBuildRecordSize    = oops.Errorf("build record has unexpected size")
	ErrBuildKeySize       = oops.Errorf("build record key has unexpected size")
	ErrBuildKeyDerivation = oops.Errorf("build record key derivation failed")
	ErrBuildAEAD          = oops.Errorf("build record AEAD failed")
)
```
Errors for Tunnel-Creation-ECIES build record operations.

```go
var (
	// ErrInvalidKeySize indicates that a provided key does not meet the required size.
	// AES-256 requires exactly 32-byte keys for both layer and IV encryption.
	ErrInvalidKeySize = oops.Errorf("invalid key size: must be 32 bytes for AES-256")

	// ErrInvalidKey indicates that a provided key is cryptographically invalid.
	// This occurs when a key is all zeros or contains invalid/weak values.
	ErrInvalidKey = oops.Errorf("invalid key: key cannot be all zeros or weak")

	// ErrCipherCreationFailed indicates that AES cipher initialization failed.
	// This typically occurs due to invalid key material or system-level cryptographic failures.
	ErrCipherCreationFailed = oops.Errorf("failed to create AES cipher block")

	// ErrNilTunnelData indicates that a nil TunnelData pointer was passed to encryption/decryption.
	// It is reserved and is not currently returned by this package: the exported
	// Encrypt/Decrypt entry points take byte slices and copy them into a
	// value-type TunnelData, so no code path can observe a nil pointer.
	ErrNilTunnelData = oops.Errorf("tunnel data cannot be nil")

	// ErrEncryptionFailed indicates that the encryption operation failed.
	// This may occur due to invalid data, corrupted keys, or cryptographic processing errors.
	ErrEncryptionFailed = oops.Errorf("tunnel encryption failed")

	// ErrDecryptionFailed indicates that the decryption operation failed.
	// This may occur due to invalid ciphertext, incorrect keys, or authentication failures.
	ErrDecryptionFailed = oops.Errorf("tunnel decryption failed")

	// ErrUnsupportedEncryptionType indicates an unsupported tunnel encryption scheme was requested.
	// Only TunnelEncryptionAES (0) and TunnelEncryptionECIES (1) are supported.
	ErrUnsupportedEncryptionType = oops.Errorf("unsupported tunnel encryption type")

	// ErrECIESEncryptionFailed indicates that ECIES encryption operation failed.
	// This may occur due to invalid public keys, data size limits, or underlying cryptographic errors.
	ErrECIESEncryptionFailed = oops.Errorf("ECIES encryption failed")

	// ErrECIESDecryptionFailed indicates that ECIES decryption operation failed.
	// This may occur due to invalid private keys, corrupted ciphertext, or authentication failures.
	ErrECIESDecryptionFailed = oops.Errorf("ECIES decryption failed")

	// ErrECIESInvalidPublicKey indicates that an invalid X25519 public key was provided for ECIES encryption.
	// ECIES public keys must be exactly 32 bytes. It is reserved and is not currently
	// returned by this package; the underlying ecies package reports its own errors.
	ErrECIESInvalidPublicKey = oops.Errorf("invalid X25519 public key for ECIES encryption")

	// ErrECIESInvalidPrivateKey indicates that an invalid X25519 private key was provided for ECIES decryption.
	// ECIES private keys must be exactly 32 bytes. It is reserved and is not currently
	// returned by this package; the underlying ecies package reports its own errors.
	ErrECIESInvalidPrivateKey = oops.Errorf("invalid X25519 private key for ECIES decryption")

	// ErrECIESInvalidCiphertext indicates that ECIES ciphertext has invalid format or size.
	// ECIES ciphertext must include ephemeral public key, nonce, and authenticated encryption tag.
	ErrECIESInvalidCiphertext = oops.Errorf("invalid ECIES ciphertext format")

	// ErrECIESOperationNotSupported indicates that an unsupported operation was attempted.
	// For example, trying to decrypt with an encryptor or encrypt with a decryptor.
	ErrECIESOperationNotSupported = oops.Errorf("ECIES operation not supported by this instance")
)
```
Error definitions for tunnel cryptographic operations using structured error
handling. These errors follow the oops pattern for consistent error wrapping and
context preservation.

#### func  DecryptBuildRequest

```go
func DecryptBuildRequest(
	state *BuildNoiseState,
	hopStaticPriv, senderPub, ciphertext []byte,
) (plaintext []byte, err error)
```
DecryptBuildRequest decrypts a BuildRequestRecord at a hop. The hop uses its own
static private key and the sender's cleartext ephemeral public key read from
bytes 16-47 of the record.

#### func  DecryptOwnBuildReply

```go
func DecryptOwnBuildReply(replyKey, ad [32]byte, recordNumber byte, ciphertext []byte) ([]byte, error)
```
DecryptOwnBuildReply decrypts a hop's own reply record.

#### func  EncryptBuildRequest

```go
func EncryptBuildRequest(
	state *BuildNoiseState,
	hopStaticPub, senderPriv, senderPub, plaintext []byte,
) (ciphertext []byte, err error)
```
EncryptBuildRequest encrypts a serialized BuildRequestRecord to a hop using the
Noise_N "es" pattern.

The caller supplies:

    - hopStaticPub: the hop's X25519 static public key from its Router Identity
      (mixed into h before the DH)
    - senderPriv / senderPub: a fresh ephemeral X25519 key pair, unique per ECIES
      hop AND per build record. The spec warns: "Ephemeral keys must be unique
      per ECIES hop, and per build record. Failing to use unique keys opens an
      attack vector for colluding hops to confirm they are in the same tunnel."
    - plaintext: the serialized record, 154 bytes (short) or 464 bytes (long)

It returns the 16-byte cleartext prefix (hop hash + sender public key) is NOT
produced here - the caller writes those - and only the encrypted region plus tag
is returned, which is len(plaintext)+16 bytes.

#### func  EncryptOwnBuildReply

```go
func EncryptOwnBuildReply(replyKey, ad [32]byte, recordNumber byte, plaintext []byte) ([]byte, error)
```
EncryptOwnBuildReply encrypts this hop's own BuildReplyRecord with
ChaCha20-Poly1305. Per the spec, 'n' is the record's position in the build
message (0-7), not always 0 as in the deprecated long-record form, and 'ad' is
the handshake hash h left over from the build request.

#### func  ObfuscateOtherBuildRecord

```go
func ObfuscateOtherBuildRecord(replyKey [32]byte, recordNumber byte, record []byte) ([]byte, error)
```
ObfuscateOtherBuildRecord applies the raw ChaCha20 stream to another hop's
already-encrypted 218-byte record, as each hop does iteratively on the reply
path. This is deliberately unauthenticated ("ChaCha20 (NOT ChaCha20/Poly1305)"),
and the record number goes in IV byte 4.

Encryption and decryption are the same XOR operation, so a hop that received a
record obfuscated with its reply key simply calls this again to undo it.

#### type AESEncryptor

```go
type AESEncryptor struct {
}
```

AESEncryptor implements tunnel encryption using dual-layer AES-256-CBC scheme.
It maintains separate cipher blocks for layer encryption and IV encryption
operations, implementing I2P's legacy tunnel cryptography for secure data
transmission through the network. The dual-layer approach provides enhanced
security by encrypting both the data payload and the initialization vector used
for subsequent encryption operations. This implements the TunnelEncryptor
interface for AES-256-CBC encryption (type 0).

#### func  NewAESEncryptor

```go
func NewAESEncryptor(layerKey, ivKey TunnelKey) (*AESEncryptor, error)
```
NewAESEncryptor creates a new AES-256-CBC tunnel encryptor with the provided
keys. Both layerKey and ivKey must be exactly 32 bytes (256 bits) for AES-256
compatibility. The function initializes separate AES cipher blocks for
dual-layer tunnel encryption, following I2P's tunnel cryptography specification
for secure data transmission. Returns a configured AESEncryptor instance or an
error if cipher creation fails due to invalid keys. Example usage: encryptor,
err := NewAESEncryptor(layerKey, ivKey)

#### func  NewTunnelCrypto

```go
func NewTunnelCrypto(layerKey, ivKey TunnelKey) (*AESEncryptor, error)
```
NewTunnelCrypto is deprecated. Use NewAESEncryptor instead. This function is
kept for backward compatibility and will be removed in a future version.

#### func (*AESEncryptor) Decrypt

```go
func (a *AESEncryptor) Decrypt(ciphertext []byte) ([]byte, error)
```
Decrypt decrypts ciphertext data using AES-256-CBC dual-layer decryption. For
AES tunnel decryption, the input should be exactly 1028 bytes of tunnel data.
Returns the 1008-byte payload from bytes 16..1024 (excluding the 16-byte IV) or
error if decryption fails. This implements the TunnelEncryptor interface for
AES-256-CBC decryption.

#### func (*AESEncryptor) Encrypt

```go
func (a *AESEncryptor) Encrypt(plaintext []byte) ([]byte, error)
```
Encrypt encrypts plaintext data using AES-256-CBC dual-layer encryption. For AES
tunnel encryption, the input should be exactly 1008 bytes of payload data (a
random 16-byte IV is then prepended); a full 1028-byte record is also accepted
and used as-is. The method creates a 1028-byte tunnel structure with a 16-byte
IV prefix. Returns the complete tunnel data (1028 bytes) or error if encryption
fails. This implements the TunnelEncryptor interface for AES-256-CBC encryption.

#### func (*AESEncryptor) Type

```go
func (a *AESEncryptor) Type() TunnelEncryptionType
```
Type returns the encryption scheme used by this encryptor (AES-256-CBC). This
implements the TunnelEncryptor interface Type() method.

#### type BuildNoiseState

```go
type BuildNoiseState struct {
}
```

BuildNoiseState is the Noise_N symmetric state (chaining key ck and handshake
hash h) for encrypting or decrypting tunnel build records to a hop.

It is initialized exactly as the spec's "KDF for Initial ck and h" requires:

    protocol_name = "Noise_N_25519_ChaChaPoly_SHA256"  (31 bytes)
    h = protocol_name || 0                  // pad to 32 bytes, do NOT hash
    ck = h                                  // copy
    h = SHA256(h)                           // MixHash(null prologue)

The pre-computed part depends only on the protocol name, so every router can
cache it; the per-hop steps are added with [BuildNoiseState.MixHash].

#### func  NewBuildNoiseState

```go
func NewBuildNoiseState() *BuildNoiseState
```
NewBuildNoiseState returns the initial Noise_N state shared by all build
requests, before any hop-specific keys are mixed in.

#### func (*BuildNoiseState) ChainKey

```go
func (s *BuildNoiseState) ChainKey() [32]byte
```
ChainKey returns the current chaining key ck. After a request record has been
encrypted/decrypted this is the root of the reply/layer key KDF chain.

#### func (*BuildNoiseState) Hash

```go
func (s *BuildNoiseState) Hash() [32]byte
```
Hash returns the current handshake hash h, which is the AEAD associated data for
the record encrypted at this state.

#### func (*BuildNoiseState) MixHash

```go
func (s *BuildNoiseState) MixHash(d []byte)
```
MixHash mixes d into the handshake hash: h = SHA-256(h || d).

#### func (*BuildNoiseState) MixKey

```go
func (s *BuildNoiseState) MixKey(sharedSecret []byte) (k [32]byte, err error)
```
MixKey performs the Noise MixKey step for a DH result:

    keydata = HKDF(salt=ck, ikm=sharedSecret, info="", 64)
    ck      = keydata[0:32]
    k       = keydata[32:64]

It returns the encryption key k for the next record and advances ck. The spec
writes this as HKDF(chainKey, sharedSecret, "", 64); kdf.StandardHKDF takes
(salt, ikm, info, n), so ck is the salt and the DH output is the ikm.

#### type BuildReplyKeys

```go
type BuildReplyKeys struct {
	// ReplyKey encrypts this hop's own reply record with ChaCha20-Poly1305 and
	// obfuscates the other records with the raw ChaCha20 stream. Both use the
	// same key.
	ReplyKey [32]byte
	// LayerKey is the AES-256 tunnel layer key (layer encryption type 0).
	LayerKey [32]byte
	// IVKey is the AES-256 tunnel IV key.
	IVKey [32]byte
	// GarlicReplyKey and GarlicReplyTag are only meaningful for the outbound
	// endpoint (OBEP); they key the garlic-encrypted reply.
	GarlicReplyKey [32]byte
	GarlicReplyTag [8]byte
	// ChainKey is the chaining key after the KDF chain, for any further use.
	ChainKey [32]byte
}
```

BuildReplyKeys are the keys derived from the chaining key after a build request
has been processed, per the spec's "KDF" section.

#### func  DeriveBuildReplyKeys

```go
func DeriveBuildReplyKeys(state *BuildNoiseState, isOBEP bool) (BuildReplyKeys, error)
```
DeriveBuildReplyKeys runs the Tunnel-Creation-ECIES reply/layer KDF chain on the
chaining key left in state after the build request was encrypted or decrypted.

The chain differs for the OBEP, which is why isOBEP is a parameter (spec: "The
KDF for the IV key at the OBEP is different from that for the other hops, even
if the reply is not garlic encrypted"):

    keydata = HKDF(ck, ZEROLEN, "SMTunnelReplyKey", 64)
    replyKey = keydata[32:64]; ck = keydata[0:32]
    keydata = HKDF(ck, ZEROLEN, "SMTunnelLayerKey", 64)
    layerKey = keydata[32:64]
      non-OBEP: ivKey = keydata[0:32]              ("because it's last")
      OBEP:     ck = keydata[0:32]
                keydata = HKDF(ck, ZEROLEN, "TunnelLayerIVKey", 64)
                ivKey = keydata[32:64]; ck = keydata[0:32]
                keydata = HKDF(ck, ZEROLEN, "RGarlicKeyAndTag", 64)
                garlicReplyKey = keydata[32:64]; garlicReplyTag = keydata[0:8]

Note on slices: the spec writes its ranges inclusively ("keydata[0:31]" means
the 32 bytes at indices 0..31), so keydata[0:7] is the 8-byte garlic reply tag -
consistent with the spec's own "32-byte garlic reply key and 8-byte garlic reply
tag".

#### type ECIESDecryptor

```go
type ECIESDecryptor struct {
}
```

ECIESDecryptor implements TunnelEncryptor using ECIES-X25519 decryption. This is
a separate struct because decryption requires a private key.

#### func  NewECIESDecryptor

```go
func NewECIESDecryptor(recipientPrivKey [32]byte) *ECIESDecryptor
```
NewECIESDecryptor creates a new ECIES tunnel decryptor using the recipient's
private key. The private key must be exactly 32 bytes (X25519 private key
format).

#### func (*ECIESDecryptor) Decrypt

```go
func (d *ECIESDecryptor) Decrypt(ciphertext []byte) ([]byte, error)
```
Decrypt decrypts the ciphertext using ECIES-X25519 scheme with the private key.
This method wraps ecies.DecryptECIESX25519() and delegates all cryptographic
operations to the existing ecies package.

#### func (*ECIESDecryptor) Encrypt

```go
func (d *ECIESDecryptor) Encrypt(plaintext []byte) ([]byte, error)
```
Encrypt is not supported by the decryptor. Returns an error.

#### func (*ECIESDecryptor) Type

```go
func (d *ECIESDecryptor) Type() TunnelEncryptionType
```
Type returns the tunnel encryption type for this decryptor.

#### func (*ECIESDecryptor) Zero

```go
func (d *ECIESDecryptor) Zero()
```
Zero securely clears the private key from memory.

#### type ECIESEncryptor

```go
type ECIESEncryptor struct {
}
```

ECIESEncryptor implements TunnelEncryptor using ECIES-X25519 encryption. This is
a thin wrapper around the existing ecies package functionality.

EXPERIMENTAL - NOT INTEROPERABLE as a tunnel scheme, and unrelated to the
deployed ECIES tunnel BUILDING crypto in this package ([EncryptBuildRequest]).
No I2P specification defines this as a tunnel layer encryption scheme. The ecies
package's one-time format is an end-to-end (destination-to-destination)
construct; Tunnel-Creation-ECIES, which does govern tunnel layer encryption,
supports only AES (type 0) and explicitly leaves any ChaCha20-based type out of
scope. Records produced here are variable length, which also conflicts with the
fixed-size tunnel record layout. Use [AESEncryptor] for real tunnels; see the
package docs for the details.

#### func  NewECIESEncryptor

```go
func NewECIESEncryptor(recipientPubKey [32]byte) *ECIESEncryptor
```
NewECIESEncryptor creates a new ECIES tunnel encryptor using the recipient's
public key. The public key must be exactly 32 bytes (X25519 public key format).
This encryptor will generate ephemeral keys for each encryption operation.

#### func (*ECIESEncryptor) Decrypt

```go
func (e *ECIESEncryptor) Decrypt(ciphertext []byte) ([]byte, error)
```
Decrypt is not supported by the encryptor: it only holds a public key, and
ECIES-X25519 decryption requires the recipient's private key. It is present to
satisfy the TunnelEncryptor interface and always returns an error. Use
ECIESDecryptor for real decryption.

#### func (*ECIESEncryptor) Encrypt

```go
func (e *ECIESEncryptor) Encrypt(plaintext []byte) ([]byte, error)
```
Encrypt encrypts the plaintext using ECIES-X25519 scheme. This method wraps
ecies.EncryptECIESX25519() and delegates all cryptographic operations to the
existing ecies package.

The encryption uses: - Ephemeral X25519 key pair - X25519 key agreement with
recipient's public key - The spec's Noise-based key derivation (see the ecies
package) - ChaCha20-Poly1305 AEAD encryption

Returns ciphertext in the ecies package's one-time format: [Elligator2-encoded
ephemeral public key 32][flags section 48][payload section N+16] - 96 bytes of
overhead plus the plaintext, so the result is variable length and is not a
1028-byte tunnel record. See the ecies package for the full wire format.

#### func (*ECIESEncryptor) Type

```go
func (e *ECIESEncryptor) Type() TunnelEncryptionType
```

#### type TunnelData

```go
type TunnelData [1028]byte
```

TunnelData represents the standardized data structure for I2P tunnel messages
(1028 bytes total). The structure follows I2P's tunnel message format where the
first 16 bytes serve as the initialization vector (IV) and the following 1008
bytes (offsets 16..1024) contain the encrypted payload data; the final 4 bytes
of the block are not processed by the AES layer. This fixed-size format ensures
network compatibility and provides consistent message boundaries for tunnel
encryption operations. The 1028-byte size aligns with I2P's network protocol
requirements for efficient data transmission. TunnelData represents the data
structure for tunnel messages (1028 bytes). Moved from: tunnel.go

#### type TunnelEncryptionType

```go
type TunnelEncryptionType uint8
```

TunnelEncryptionType distinguishes between tunnel *layer* encryption schemes -
the symmetric encryption of each 1028-byte tunnel message, which is a different
concern from tunnel *building* (which is ECIES-based; see
[EncryptBuildRequest]). I2P's specifications define only AES (type 0) for layer
encryption. Use [TunnelEncryptionAES] for anything that has to talk to a real
router; [TunnelEncryptionECIES] is experimental and not interoperable.

```go
const (
	// TunnelEncryptionAES is the AES-256-CBC tunnel layer encryption scheme,
	// and the only layer encryption type defined by the I2P specifications
	// (Tunnel-Creation-ECIES: "The only layer encryption currently supported is
	// type 0, which is AES"). Use this for anything that must interoperate.
	// It uses dual-layer AES encryption with separate layer and IV keys.
	// Tunnel records are 1028 bytes: a 16-byte IV prefix followed by the
	// encrypted payload region (bytes 16..1024 are CBC-processed; the final 4
	// bytes are carried through unchanged).
	TunnelEncryptionAES TunnelEncryptionType = 0

	// TunnelEncryptionECIES is EXPERIMENTAL and NOT interoperable as a tunnel
	// LAYER encryption scheme. No I2P specification defines an ECIES/ChaCha20
	// tunnel layer encryption type: Tunnel-Creation-ECIES lists type 1 only as
	// "for future (ChaCha?)" and says adding such types "is a topic for
	// additional research, and is not currently a part of this specification".
	// (ECIES-X25519 IS the deployed standard for tunnel BUILDING - see
	// [EncryptBuildRequest] - but that is a different layer, and this value
	// implements neither of those formats.) The ECIES-X25519-AEAD-Ratchet spec
	// this is often assumed to implement is end-to-end (destination to
	// destination) and does not define tunnel layer encryption at all.
	//
	// This value wraps the ecies package's one-time format, so records are
	// variable length: 96 bytes of overhead plus the plaintext (Elligator2-
	// encoded ephemeral key + flags section + payload + tag). Measured: a
	// 1-byte payload yields 97 bytes, a 222-byte payload 318 bytes, and a
	// full 1008-byte tunnel payload 1104 bytes - larger than the fixed
	// 1028-byte AES record. Variable-length records also defeat the fixed-size
	// tunnel layout that stops intermediate hops from observing payload sizes.
	//
	// The local value 1 is this package's own choice; it is not the spec's
	// layer encryption type 1, and it is distinct from the LS2 crypto type 4
	// used in LeaseSet2 records. Do not advertise it to a router.
	TunnelEncryptionECIES TunnelEncryptionType = 1
)
```

#### func (TunnelEncryptionType) String

```go
func (t TunnelEncryptionType) String() string
```
String returns the human-readable name of the encryption type for logging and
debugging.

#### type TunnelEncryptor

```go
type TunnelEncryptor interface {
	// Encrypt encrypts plaintext data and returns the ciphertext.
	// For AES: accepts 1008 bytes of payload (a random 16-byte IV is prepended)
	// or a full 1028-byte record, and returns a 1028-byte record. Note that only
	// bytes 16..1024 of the record are CBC-processed; the final 4 bytes are left
	// as provided.
	// For ECIES: accepts variable-length data up to the ECIES max plaintext size
	// and returns the ECIES one-time format (96 bytes of overhead plus the
	// payload).
	// Returns error if encryption fails due to invalid keys or cryptographic operations.
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext data and returns the plaintext.
	// For AES: expects 1028 bytes of tunnel data and returns the 1008-byte
	// payload from bytes 16..1024 (excluding the 16-byte IV prefix).
	// For ECIES: expects ECIES-formatted ciphertext, returns original plaintext
	// Returns error if decryption fails due to invalid keys, corrupted data, or authentication failures.
	Decrypt(ciphertext []byte) ([]byte, error)

	// Type returns the encryption scheme used by this encryptor.
	// This enables routers to identify and handle different tunnel encryption formats.
	Type() TunnelEncryptionType
}
```

TunnelEncryptor defines the interface for tunnel-level encryption operations.
The abstraction has two implementations: AES-256-CBC, the only scheme the I2P
specifications define for tunnel *layer* encryption, and ECIES-X25519, an
experimental wrapper around the end-to-end ecies package that is not a tunnel
scheme at all (see [TunnelEncryptionECIES]).

Note that tunnel *building* is a separate concern from tunnel layer encryption
and is ECIES-based in current I2P; that crypto lives in this package's
build-record functions ([EncryptBuildRequest] and friends), not in this
interface. Implementations must provide secure encryption/decryption with proper
error handling.

#### func  NewTunnelEncryptor

```go
func NewTunnelEncryptor(encType TunnelEncryptionType, layerKey, ivKey TunnelKey) (TunnelEncryptor, error)
```
NewTunnelEncryptor creates a new tunnel encryptor based on the specified
encryption type. This factory function provides a unified interface for creating
both AES and ECIES encryptors.

For AES encryption (type 0), the only scheme defined by the I2P specifications:

    - layerKey: 32-byte AES-256 key for data layer encryption
    - ivKey: 32-byte AES-256 key for IV encryption

For ECIES encryption (type 1), which is experimental and not interoperable:

    - recipientPubKey: 32-byte X25519 public key (layerKey parameter)
    - ivKey parameter is ignored for ECIES

Returns configured TunnelEncryptor or error if creation fails due to invalid
parameters.

#### type TunnelIV

```go
type TunnelIV []byte
```

TunnelIV represents the initialization vector for tunnel message encryption
operations. The IV provides randomization for CBC mode encryption and should be
unique for each tunnel message to prevent cryptographic attacks. In I2P tunnel
messages, the IV occupies the first 16 bytes of the TunnelData structure and
serves as the randomization source for CBC encryption. IVs must be unpredictable
but do not need to be secret, following standard cryptographic practices.
TunnelIV represents the initialization vector for a tunnel message. Moved from:
tunnel.go

#### type TunnelKey

```go
type TunnelKey [32]byte
```

TunnelKey represents a symmetric AES-256 key for encrypting tunnel messages (32
bytes). Each tunnel operation requires two separate TunnelKey instances: one for
layer encryption and another for IV encryption. The 32-byte length provides
256-bit security strength compatible with AES-256 encryption used in I2P tunnel
cryptography. These keys should be cryptographically random and generated using
secure random number generators.

⚠️ CRITICAL SECURITY WARNING ⚠️ Always use NewTunnelKey() to create instances.
Do NOT construct directly with &TunnelKey{} or TunnelKey{}.

Example usage:

    // WRONG - Creates invalid zero-value key
    var key TunnelKey

    // CORRECT - Validates key data
    key, err := NewTunnelKey(keyBytes)

#### func  NewTunnelKey

```go
func NewTunnelKey(data []byte) (*TunnelKey, error)
```
NewTunnelKey creates a validated tunnel key from bytes.

The input data must be exactly 32 bytes for AES-256 compatibility. Additionally,
the key cannot be all zeros as this would provide no cryptographic security
(weak/invalid key).

Returns an error if:

    - data length is not exactly 32 bytes
    - data is all zeros (cryptographically invalid)

The returned key is a defensive copy - modifications to the input slice will not
affect the key.



tunnel 

github.com/go-i2p/crypto/tunnel

[go-i2p template file](/template.md)
