// Package ed25519 provides Ed25519 digital signatures for I2P.
//
// Ed25519 is a modern signature algorithm. It produces small signatures,
// verifies quickly, and is resistant to many of the mistakes that make older
// signature schemes unsafe. It is defined in RFC 8032 and is the standard
// signature type for I2P destinations.
//
// # How it works
//
//   - The signer uses its private key to create a 64-byte signature.
//   - A verifier checks the signature against the signer's public key.
//
// Note: Ed25519 is for signatures only. Use the curve25519 package for
// encryption.
//
// # Private key encoding
//
// The I2P specification's SigningPrivateKey table (common-structures.md
// §SigningPrivateKey) gives EdDSA_SHA512_Ed25519 a length of 32 bytes, stored
// little-endian. That 32 bytes is the key *seed*. Go's crypto/ed25519 keeps a
// private key as the 64-byte expansion seed‖publicKey, and [Ed25519PrivateKey]
// follows that in-memory layout, so [Ed25519PrivateKey.Bytes] emits 64 bytes.
//
// When reading or writing the format a Java router uses - router.config,
// i2pdirector.xml, an I2CP SigningPrivateKey, or a Destination handoff - use the
// 32-byte seed form: [NewEd25519PrivateKeyFromSeed] to import and
// [Ed25519PrivateKey.Seed] to export.
//
// See RFC 8032 for the Ed25519 specification:
// https://datatracker.ietf.org/doc/html/rfc8032
package ed25519
