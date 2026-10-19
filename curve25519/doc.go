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
// # Relationship to the I2P ECIES specification
//
// This package is a generic X25519 + ChaCha20-Poly1305 helper. Its wire format
// is NOT the I2P ECIES-X25519-AEAD-Ratchet format described at
// https://i2p.net/en/docs/specs/ecies/ : the spec's New Session / one-time
// message uses an Elligator2-encoded ephemeral key, a Noise IK/"es" key
// schedule, a separate authenticated flags/static section, and a counter nonce
// whose associated data is the running mix-hash. Here the ephemeral key is sent
// raw, the key is derived with a single plain HKDF call, the nonce is random,
// and there is no associated data.
//
// Use the ecies package for anything that must interoperate with I2P routers.
//
// # X25519 is not a signing key
//
// This package provides encryption keys only. There is no I2P signature type
// based on X25519: cryptography.md §Signatures enumerates DSA-SHA1, the three
// ECDSA curves, EdDSA-SHA512-Ed25519, RedDSA-SHA512-Ed25519 and the offline-only
// RSA and Ed25519ph variants, and §New Signature Algorithms states "Signature
// type is encoded in the Destination and Router Identity". X25519 appears in the
// spec strictly for key agreement (ecies.md §2: "DH Function: X25519 ... as
// specified in RFC-7748"). Accordingly [Curve25519PrivateKey] and
// [Curve25519PublicKey] expose NewDecrypter/NewEncrypter but no NewSigner or
// NewVerifier. Use ed25519, ed25519ph, red25519, dsa, ecdsa or rsa for signing.
package curve25519
