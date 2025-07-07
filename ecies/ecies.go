// Package ecies implements ECIES-X25519-AEAD-Ratchet encryption as specified in I2P Proposal 144.
//
// This package provides the modern I2P encryption scheme that replaces ElGamal/AES+SessionTags.
// It implements ephemeral-static and ephemeral-ephemeral Diffie-Hellman key agreement
// using X25519, combined with ChaCha20-Poly1305 AEAD encryption.
//
// The implementation follows I2P Proposal 144 specification:
// https://geti2p.net/spec/proposals/144-ecies-x25519-aead-ratchet
package ecies
