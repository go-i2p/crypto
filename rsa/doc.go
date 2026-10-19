// Package rsa provides RSA (Rivest-Shamir-Adleman) signing for I2P.
//
// # Deprecated: legacy algorithm
//
// RSA is a legacy signature scheme in I2P. It is kept for compatibility with
// older routers and for verifying legacy data, but new code should use the
// ed25519 or red25519 packages, which are faster and more secure.
//
// RSA is a widely used public-key algorithm. A key pair consists of a public
// key (for verifying signatures) and a private key (for creating them). This
// package supports 2048-bit, 3072-bit, and 4096-bit keys.
//
// Approximate symmetric-equivalent security strengths (NIST SP 800-57):
// RSA-2048 ≈ 112 bits, RSA-3072 ≈ 128 bits, RSA-4096 ≈ 140-152 bits.
//
// # How it works
//
//   - The signer hashes the data with a key-size-appropriate hash: SHA-256
//     for RSA-2048, SHA-384 for RSA-3072, and SHA-512 for RSA-4096. These
//     match the I2P signature types RSA_SHA256_2048 (4), RSA_SHA384_3072 (5)
//     and RSA_SHA512_4096 (6).
//   - The signer creates a signature using its private key.
//   - A verifier checks the signature against the signer's public key.
//
// # Key construction
//
// Always use the provided constructors (for example NewRSA2048PrivateKey) to
// create keys. Constructing a key type directly with a zero value produces an
// invalid key.
//
// See RFC 3447 for the RSA specification:
// https://datatracker.ietf.org/doc/html/rfc3447
package rsa
