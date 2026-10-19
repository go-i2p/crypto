// Package tunnel implements the cryptography used to protect I2P tunnel
// messages, the small packets that carry data between routers.
//
// # What this package does
//
// When I2P routers send data to each other, the data travels inside tunnel
// messages. This package encrypts and decrypts those messages. It supports
// two schemes, selected by a local encryption-type value:
//
//   - AES-256-CBC (TunnelEncryptionAES, value 0): the scheme I2P actually uses
//     for tunnel layer encryption. It uses two separate AES-256 keys (one for
//     the payload, one for the IV) in CBC mode, with a fixed 1028-byte message
//     layout. This is the only interoperable option.
//   - ECIES-X25519 (TunnelEncryptionECIES, value 1): EXPERIMENTAL, NOT part of
//     any I2P specification, and NOT interoperable with any I2P router. It
//     wraps the ecies package's end-to-end one-time format. See "What the
//     specifications actually say" below before using it.
//
// Note that these local values (0 and 1) are an internal choice of this
// package. They are not the same as the "crypto type" field in the I2P
// LeaseSet2 (LS2) records, where ECIES-X25519 is identified by crypto type 4.
//
// # How it fits the I2P specification
//
// The legacy AES-256-CBC scheme follows the ElGamal/AES+SessionTags
// specification and the Tunnel-Creation-ECIES layer-key derivation.
//
// The ECIES-X25519 scheme does not follow any tunnel specification. It is
// provided for experimentation only and must not be offered to a real router
// as a tunnel encryption type.
//
// # What the specifications actually say
//
// The I2P ECIES-X25519-AEAD-Ratchet specification (Proposal 144) is an
// end-to-end, destination-to-destination protocol. It is explicit that
// "intermediate hops cannot distinguish new from old crypto", and it does not
// define tunnel layer encryption at all. Wrapping its one-time message format
// in a tunnel encryptor does not make it a tunnel scheme.
//
// Tunnel layer encryption is defined by Tunnel-Creation-ECIES, which says:
//
//	"The only layer encryption currently supported is type 0, which is AES.
//	This is unchanged from previous specifications... Adding new layer
//	encryption types, for example ChaCha20, is a topic for additional
//	research, and is not currently a part of this specification."
//
// Its layer-encryption-type field table likewise lists "0 for AES (as in
// current tunnels); 1 for future (ChaCha?)" - an open question, not a defined
// format. So the local value 1 here is not the spec's type 1, and records
// produced by it are not understood by any deployed router.
//
// Fixed record sizes also matter for tunnel privacy: the spec keeps layer
// records a constant size so hops cannot observe payload sizes. The ECIES
// scheme here produces variable-length output (96 bytes of overhead plus the
// plaintext), which defeats that property. See [TunnelEncryptionECIES] for the
// measured sizes.
//
// See the official specifications:
//   - ElGamal/AES+SessionTags: https://i2p.net/en/docs/specs/elgamal-aes/
//   - Tunnel-Creation-ECIES (layer keys, build records):
//     https://i2p.net/en/docs/specs/tunnel-creation-ecies/
//   - ECIES-X25519-AEAD-Ratchet (end-to-end only, NOT tunnel encryption):
//     https://i2p.net/en/docs/specs/ecies/
//
// # Message layout
//
// A tunnel message is a fixed 1028-byte block. In the legacy AES scheme the
// first 16 bytes are the initialization vector (IV) and the following 1008
// bytes (offsets 16..1024) are the encrypted payload; the final 4 bytes of the
// block are not processed and are carried through unchanged.
//
// The experimental ECIES scheme does not produce a 1028-byte block at all. It
// produces a variable-length one-time ciphertext of [Elligator2-encoded
// ephemeral public key 32][flags section 48][payload section N+16], as
// described in the ecies package: 96 bytes of overhead plus the plaintext. For
// a 1-byte payload that is 97 bytes, for 1008 bytes of payload it is 1104
// bytes - larger than the AES record, not smaller. A caller that needs to
// place its output in a tunnel-sized buffer must pad and frame it itself.
package tunnel
