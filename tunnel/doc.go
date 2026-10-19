// Package tunnel implements the cryptography used to protect I2P tunnels.
//
// # What this package does
//
// I2P protects a tunnel in two different places, and the two use different
// cryptography. Conflating them is the single most common mistake when reading
// tunnel crypto, so this package keeps them explicitly separate:
//
//   - Tunnel BUILDING - the TunnelBuild / Short Tunnel Build messages that
//     establish a tunnel hop by hop. This is ECIES-X25519 with ChaCha20-Poly1305,
//     and it is deployed: the Low-level Cryptography spec states plainly that
//     "X25519 tunnel creation has replaced ElGamal tunnel creation", and
//     Tunnel-Creation-ECIES is "accurate for 0.9.66", with the short-record form
//     implemented since release 0.9.51. See [BuildNoiseState] and
//     [EncryptBuildRequest].
//   - Tunnel LAYER encryption - the symmetric encryption of every 1028-byte
//     tunnel message as it flows through the established tunnel. The only layer
//     encryption type defined by the specification is type 0, which is
//     AES-256-CBC. See [AESEncryptor].
//
// So ECIES is the standard for *building* tunnels, and AES is the standard for
// *encrypting the traffic inside* them. Both are current; neither replaces the
// other, because they operate at different layers.
//
// # Scope: primitives, not protocol
//
// This package holds cryptographic primitives only. The build-record functions
// ([EncryptBuildRequest], [DecryptBuildRequest], [DeriveBuildReplyKeys],
// [EncryptOwnBuildReply], [ObfuscateOtherBuildRecord]) implement the key
// schedule, the AEAD over an already-serialized record, and the reply/layer KDF
// chain. The record byte layouts themselves - tunnel ID, next-router identity
// hash, flags, request time, the build-options Mapping, padding, record
// randomization, "fake" records, and VariableTunnelBuild message assembly - are
// common data structures and protocol, and belong in github.com/go-i2p/common
// and the Noise packages, not here. Callers pass in the serialized plaintext
// record and receive the wire ciphertext.
//
// # Tunnel building (ECIES-X25519)
//
// Tunnel-Creation-ECIES builds on the Noise protocol
// Noise_N_25519_ChaChaPoly_SHA256, a one-way "N" pattern: the creator (Alice)
// does an ephemeral-static X25519 DH to each hop (Bob) and seals the build
// request record with ChaCha20-Poly1305. The chaining key left over after that
// request derives the reply key, the AES layer key, the AES IV key and, at the
// outbound endpoint, the garlic reply key and tag.
//
// Two record sizes are specified:
//
//   - Short records (current, 0.9.51+): 154-byte request plaintext and 202-byte
//     reply plaintext, both producing 218-byte encrypted records. The 218-byte
//     figure is the whole wire record: for a request it is 16 (hop identity hash)
//   - 32 (sender ephemeral key) + 154 (ciphertext) + 16 (Poly1305 tag); for a
//     reply there is no cleartext prefix, so it is 202 + 16.
//   - Long records (deprecated, 0.9.48): 464-byte request and 512-byte reply
//     plaintext, both producing 528-byte encrypted records, kept that size for
//     ElGamal compatibility. The spec marks this form "Deprecated, obsolete. Use
//     the Short Record format".
//
// Ephemeral keys must be unique per ECIES hop and per build record; the spec
// warns that reusing them "opens an attack vector for colluding hops to confirm
// they are in the same tunnel".
//
// # Tunnel layer encryption (AES-256-CBC)
//
// [TunnelEncryptionAES] (value 0) is the scheme I2P uses for tunnel layer
// encryption: two separate AES-256 keys (one for the payload, one for the IV) in
// CBC mode, over a fixed 1028-byte message. This is the only interoperable layer
// option, and Tunnel-Creation-ECIES derives its keys with the KDF above rather
// than transmitting them in the build record.
//
// The layer-encryption-type field in a build request record reads "0 for AES (as
// in current tunnels); 1 for future (ChaCha?)". The spec is explicit:
//
//	"The only layer encryption currently supported is type 0, which is AES...
//	Adding new layer encryption types, for example ChaCha20, is a topic for
//	additional research, and is not currently a part of this specification."
//
// So type 1 is reserved-but-undefined, implemented by no router, and this
// package offers no constant for it: [NewTunnelEncryptor] accepts only
// [TunnelEncryptionAES] and returns [ErrUnsupportedEncryptionType] for anything
// else. (This package previously exported an ECIES layer encryptor under the
// value 1. It wrapped the ecies package's *end-to-end* one-time format, which is
// destination-to-destination rather than a tunnel layer scheme, and produced
// variable-length output - defeating the fixed-size tunnel layout whose purpose
// is to stop intermediate hops from observing payload sizes. It has been
// removed.)
//
// Note also that the layer-encryption-type field is not the "crypto type" field
// of the I2P LeaseSet2 (LS2) records, where ECIES-X25519 is identified by crypto
// type 4. ECIES-X25519 IS the deployed standard for tunnel *building* (see
// [EncryptBuildRequest]); that is a different layer from record encryption.
//
// See the official specifications:
//   - Tunnel-Creation-ECIES (build records, layer keys - the current tunnel
//     building standard): https://i2p.net/en/docs/specs/tunnel-creation-ecies/
//   - Low-level Cryptography (AES layer encryption, ElGamal legacy):
//     https://i2p.net/en/docs/specs/cryptography/
//   - ElGamal/AES+SessionTags (legacy end-to-end):
//     https://i2p.net/en/docs/specs/elgamal-aes/
//   - ECIES-X25519-AEAD-Ratchet (end-to-end, destination to destination):
//     https://i2p.net/en/docs/specs/ecies/
//
// # Message layout
//
// A tunnel message is a fixed 1028-byte block laid out per the Tunnel Message
// specification (https://i2p.net/en/docs/specs/tunnel-message/, "Tunnel Message
// (Encrypted)"):
//
//	bytes 0..3     Tunnel ID        4 bytes, cleartext, nonzero
//	bytes 4..19    IV               16 bytes
//	bytes 20..1027 Encrypted Data   1008 bytes
//
// In the AES layer scheme the IV at bytes 4..19 is transformed with the IV key
// before and after the payload is processed, and the whole 1008-byte region at
// bytes 20..1027 is CBC-encrypted. Nothing in the block is left unencrypted
// except the 4-byte tunnel ID, which is caller framing. See [TunnelIDSize],
// [TunnelIVOffset], [TunnelIVSize], [TunnelPayloadOffset] and
// [TunnelPayloadSize].
package tunnel
