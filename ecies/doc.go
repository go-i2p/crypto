// Package ecies implements ECIES-X25519-AEAD-Ratchet, the modern end-to-end
// encryption scheme for I2P.
//
// # What this package does
//
// I2P lets two routers talk to each other without anyone in the middle being
// able to read the messages. This package is the building block that makes
// that possible. It replaces the older ElGamal/AES+SessionTags scheme with a
// faster, smaller, and more secure design.
//
// The scheme is built from three well-known pieces:
//
//   - X25519: a way for two parties to agree on a shared secret over an
//     insecure channel. Each key is 32 bytes. See RFC 7748.
//   - ChaCha20-Poly1305: an authenticated encryption scheme (AEAD) that both
//     hides the message and proves it was not tampered with. See RFC 8439.
//   - A ratchet: a one-way chain of keys that gives forward secrecy, meaning
//     that compromising one key does not reveal past messages.
//
// # How it fits the I2P specification
//
// This package implements the core primitives of the I2P ECIES-X25519-AEAD
// scheme (Proposal 144), which is supported by I2P routers as of version
// 0.9.46. In the network's LeaseSet2 (LS2) records, this scheme is identified
// by crypto type 4, which marks a 32-byte little-endian X25519 public key.
// (Crypto type 0 is the legacy ElGamal scheme; types 1-3 are reserved for a
// different ECIES variant.)
//
// The one-shot EncryptECIESX25519/DecryptECIESX25519 functions provide a
// self-contained ephemeral-static X25519 + ChaCha20-Poly1305 exchange. They
// are a simplified form of the spec's "New Session" message: the ephemeral
// key is not Elligator2-encoded, the nonce is fully random rather than
// zero-prefixed, and the key is derived with a single HKDF call rather than
// the spec's Noise-based chain. See AUDIT.md for the full list of
// deviations from the wire format.
//
// See the official specification for the full protocol:
// https://i2p.net/en/docs/specs/ecies/
//
// # The two main operations
//
// EncryptECIESX25519 and DecryptECIESX25519 implement a one-shot
// ephemeral-static exchange: the sender generates a fresh ephemeral key,
// agrees a shared secret with the recipient's static key, and encrypts with
// ChaCha20-Poly1305. The ciphertext is laid out as
// [ephemeral public key][nonce][AEAD ciphertext].
//
// For long-lived sessions that need forward secrecy, see SessionState, which
// layers the three ratchets (session tag, symmetric key, and DH ratchet) on
// top of the same primitives.
//
// # Key sizes
//
//   - Public and private keys: 32 bytes (X25519)
//   - Nonce: 12 bytes (ChaCha20-Poly1305)
//   - Authentication tag: 16 bytes (Poly1305)
//   - Maximum plaintext: 1024 bytes
package ecies
