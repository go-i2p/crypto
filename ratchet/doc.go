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
//   - SessionTagRatchet: derives the short session tags that identify a
//     message's place in a session.
//   - SymmetricKeyRatchet: derives the message encryption keys, advancing
//     one step per message.
//   - DHRatchet: periodically performs a fresh X25519 Diffie-Hellman
//     exchange to refresh the root key, which is the strongest form of
//     forward secrecy.
//
// # How it fits the I2P specification
//
// These ratchets are the "ratchets" that replace the old SessionTags in the
// ECIES-X25519-AEAD-Ratchet specification. The design borrows the idea from
// the Signal double ratchet. The key-derivation steps here use
// HMAC-SHA256 with "MessageKey"/"NextChainKey" info strings, which is a
// Signal-style construction rather than the spec's Noise-based MixKey.
// See AUDIT.md for the specific deviations.
//
// See the official specification for the full protocol:
// https://i2p.net/en/docs/specs/ecies/
//
// # A note on construction
//
// Always create a DHRatchet with NewDHRatchet rather than a struct literal,
// so that its internal state is initialized correctly.
package ratchet
