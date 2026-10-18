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
// data-phase rules: a maximum of 65535 messages per tag set (after which a
// DH ratchet step is required, see ErrTagsetExhausted) and a receiver
// lookahead window (default 32, maximum 128) for out-of-order session tags.
// NewSessionFromECIES bridges an ecies.SessionState into a spec-compliant
// Session by deriving the root and chain keys with the spec's
// DH_INITIALIZE and TagAndKeyGenKeys KDFs.
package ratchet
