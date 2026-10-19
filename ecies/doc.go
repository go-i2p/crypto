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
// The one-shot EncryptECIESX25519/DecryptECIESX25519 functions implement the
// spec's one-time (IK) pattern: the ephemeral key is
// Elligator2-encoded for the wire, the key is derived with the spec's
// Noise-based chain, and the ciphertext uses the spec's two-section layout.
// See the "The two main operations" section below for the wire format.
//
// One thing to know before using them on real traffic: these functions encrypt
// and decrypt opaque byte buffers. Section 1d requires the one-time *payload*
// to contain a DateTime block and usually Garlic Clove blocks, and section 5
// defines that block format (1-byte type, 2-byte big-endian length) and its
// ordering rules. This package does not build, parse or validate payload
// blocks, so a caller composing an I2P message must format the payload itself.
//
// # Specification coverage
//
// Implemented: the one-time format and its key schedule (sections 1d and the
// no-static-key path of 1f), the Elligator2 encoding of section 2a, and the
// AEAD rules of section 3.
//
// Not implemented: the New Session message with a static key (sections 1a and
// 1b), the New Session Reply (section 1g) and its SessionReplyTags KDF, the
// Existing Session message framing of section 1h (the ratchet package supplies
// the session tag, per-message key and nonce that 1h requires, but no message
// framing), and the payload block format of section 5. The scheme is therefore
// not a complete replacement for ElGamal/AES+SessionTags on its own; see the
// ratchet package docs for the data-phase gaps.
//
// See the official specification for the full protocol:
// https://i2p.net/en/docs/specs/ecies/
//
// # The two main operations
//
// EncryptECIESX25519 and DecryptECIESX25519 implement a one-shot
// ephemeral-static exchange: the sender generates a fresh ephemeral key,
// agrees a shared secret with the recipient's static key, and encrypts with
// ChaCha20-Poly1305.
//
// The ciphertext follows the spec's one-time format (section 1d). It has
// three parts:
//
//   - An Elligator2-encoded ephemeral public key (32 bytes).
//   - A flags section: 32 bytes of ChaCha20 ciphertext plus a 16-byte
//     Poly1305 tag (48 bytes). The decrypted flags are 32 bytes of zeros.
//   - A payload section: the ChaCha20 ciphertext of the message plus a
//     16-byte Poly1305 tag.
//
// The total overhead is 96 bytes. The two sections are authenticated
// separately, so a tampered flags section is rejected without decrypting the
// payload. The key is derived with the spec's Noise "IK" + "es" + "N"
// schedule (section 1f), not a single HKDF call.
//
// For long-lived sessions that need forward secrecy, see [ratchet.Session],
// which layers the three ratchets (session tag, symmetric key, and DH ratchet)
// on top of the same primitives and implements the spec's data-phase KDFs
// exactly, including the mandatory Noise Split() that keeps the inbound and
// outbound chains independent. Note that a Session created here is still not a
// complete data phase: the New Session Reply handshake that seeds it, and the
// payload block format, are not implemented. This package previously exposed a SessionState convenience type
// whose static-static initial key derivation used non-spec KDF parameters; it
// was not a spec-mandated wire format and has been removed. Use
// [ratchet.Session] for ratcheted sessions.
//
// # Key sizes
//
//   - Public and private keys: 32 bytes (X25519)
//   - Nonce: 12 bytes (ChaCha20-Poly1305)
//   - Authentication tag: 16 bytes (Poly1305)
//   - Maximum plaintext: 65519 bytes (spec section 5: a 65535-byte ChaChaPoly
//     frame minus the 16-byte Poly1305 tag)
package ecies
