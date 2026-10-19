// Package ratchet implements the key-ratcheting mechanisms used by modern I2P
// encryption.
//
// # What a ratchet is
//
// A ratchet is a one-way chain of keys. You start with one key and can
// derive the next key from it, but you cannot go backwards. This gives
// forward secrecy: if an attacker later steals the current key, they still
// cannot read messages that were encrypted with earlier keys, because those
// earlier keys can no longer be recovered.
//
// # The three ratchets
//
// I2P's ECIES-X25519-AEAD-Ratchet protocol (Proposal 144) uses three
// ratchets together. This package provides each one:
//
//   - TagRatchet: derives the short session tags that identify a
//     message's place in a session.
//   - SymmetricRatchet: derives the message encryption keys, advancing
//     one step per message.
//   - DHRatchet: periodically performs a fresh X25519 Diffie-Hellman
//     exchange to refresh the root key, which is the strongest form of
//     forward secrecy.
//
// # How it fits the I2P specification
//
// These ratchets are the "ratchets" that replace the old SessionTags in the
// ECIES-X25519-AEAD-Ratchet specification. The design borrows the idea from
// the Signal double ratchet.
//
// The key-derivation steps use HKDF-SHA256 (RFC 5869) with the spec's info
// strings, matching the I2P specification:
//
//   - DH_INITIALIZE / DH_INITIALIZEFull: HKDF(rootKey, k, "KDFDHRatchetStep", 64)
//     followed by HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64).
//   - TagRatchet: HKDF(chainKey, ZEROLEN, "STInitialization", 64) to
//     seed, then HKDF(chainKey, SESSTAG_CONSTANT, "SessionTagKeyGen", 64) per
//     step.
//   - SymmetricRatchet: HKDF(chainKey, ZEROLEN, "SymmetricRatchet", 64).
//   - Split: HKDF(ck, ZEROLEN, "", 64), the Noise function the spec imports by
//     name in section 4a to separate the inbound and outbound chains.
//
// The info strings the ECIES spec mandates are exactly KDFDHRatchetStep,
// TagAndKeyGenKeys, STInitialization, SessionTagKeyGen, SymmetricRatchet,
// XDHRatchetTagSet and SessionReplyTags. Of these, SessionReplyTags belongs to
// the New Session Reply handshake and is not used anywhere in this package.
//
// See the official specification for the full protocol:
// https://i2p.net/en/docs/specs/ecies/
//
// Historical note: an earlier revision of this package used a Signal-style
// HMAC-SHA256 construction ("MessageKey"/"NextChainKey") that did not match
// the spec. That was corrected to the HKDF construction above.
//
// # A note on construction
//
// Always create a DHRatchet with NewDHRatchet rather than a struct literal,
// so that its internal state is initialized correctly.
//
// # Session
//
// The Session type ties the three ratchets together and enforces the spec's
// data-phase rules: message numbers 0..65535 inclusive per tag set (after
// which a DH ratchet step is required, see ErrTagsetExhausted) and a receiver
// lookahead window (default 32, maximum 128) for out-of-order session tags.
//
// Each direction of traffic keeps its own symmetric ratchet, tag ratchet,
// message counter and lookahead window. That separation is mandated by spec
// section 4a: "After the final handshake KDF on bound sessions, Bob and Alice
// must run the Noise Split() function on the resulting CipherState to create
// independent symmetric and tag chain keys for inbound and outbound sessions."
// [Split] implements it, and [NewSessionFromECIESWithRole] applies it.
//
// Because both peers run the same split over the same key, the two endpoints of
// a session must be given opposite roles: the initiator sends on the first
// Split key and receives on the second, the responder does the reverse. When a
// single program creates both sides (tests, in-process tunnels), construct one
// with [RoleInitiator] and the other with [RoleResponder]; two sessions created
// with the same role are the same session and their outbound chains collide.
// [NewSessionFromECIES] is the initiator-side convenience wrapper.
//
// A session created from raw ECIES key material applies the spec's Split,
// DH_INITIALIZE and TagAndKeyGenKeys KDFs, but its initial seed is not
// handshake-derived, so the result will not interoperate with a Java I2P
// router; see the function's own documentation for the details and scope
// boundary.
//
// # What is not implemented
//
// The full bound-session protocol is out of scope for this package: the New
// Session Reply handshake (spec section 1g) and its SessionReplyTags KDF, the
// payload block format and ordering rules (section 5), the NextKey/ACK blocks,
// and the key / tag-set ID progression of section 4a (tag set ID = 1 + Alice's
// key ID + Bob's key ID, maximum key ID 32767) are all absent. PerformDHRatchet
// advances only the outbound direction; the inbound half of a NextKey exchange
// is [Session.PerformReceivingDHRatchet], but nothing here parses or emits the
// NextKey block that drives it.
package ratchet
