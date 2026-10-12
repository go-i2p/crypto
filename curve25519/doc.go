// Package curve25519 provides X25519 elliptic-curve encryption for I2P.
//
// X25519 is a key-exchange algorithm built on the Curve25519 elliptic curve.
// Two parties each generate a key pair, exchange their public keys, and
// independently compute the same shared secret. That shared secret is then
// used to encrypt data with ChaCha20-Poly1305.
//
// # How it works
//
//   - The sender generates a short-lived (ephemeral) key pair.
//   - The sender combines its ephemeral private key with the recipient's
//     public key to derive a shared secret.
//   - The shared secret is stretched with HKDF into an encryption key.
//   - Data is encrypted with ChaCha20-Poly1305.
//
// The encrypted output is laid out as:
//
//	[zero padding][ephemeral public key][nonce][ciphertext + tag]
//
// This package is used by I2P network protocols that need to encrypt data to
// a specific destination. For the full ECIES-X25519-AEAD-Ratchet scheme, see
// the ecies package and the I2P specification:
// https://i2p.net/en/docs/specs/ecies/
package curve25519
