// Package ed25519ph provides Ed25519ph (pre-hashed) digital signature functionality.
//
// Ed25519ph is the pre-hashed variant of Ed25519 defined in RFC 8032 §5.1.
// Unlike PureEdDSA (standard Ed25519), Ed25519ph hashes the message with SHA-512
// before signing, using a domain separation tag to distinguish signatures from
// PureEdDSA. This makes Ed25519ph suitable for signing large messages or when
// the signer cannot buffer the entire message before signing.
//
// IMPORTANT: Ed25519ph signatures are NOT interchangeable with standard Ed25519
// (PureEdDSA) signatures. An Ed25519ph signature cannot be verified by a PureEdDSA
// verifier and vice versa, even though both use the same key format.
//
// For standard I2P Ed25519 signatures (EdDSA-SHA512-Ed25519), use the ed25519
// package instead. This package exists for applications that specifically require
// the pre-hashed variant.
//
// # Private key encoding
//
// common-structures.md §SigningPrivateKey gives EdDSA_SHA512_Ed25519ph a length
// of 32 bytes, stored little-endian. That 32 bytes is the key *seed*; Go's
// crypto/ed25519 keeps a private key as the 64-byte expansion seed‖publicKey,
// and [Ed25519phPrivateKey] follows that in-memory layout. Use
// [NewEd25519phPrivateKeyFromSeed] to import and [Ed25519phPrivateKey.Seed] to
// export the 32-byte form a Java router uses for offline signing.
package ed25519ph
