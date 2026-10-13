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
// # How it works
//
//   - The signer hashes the data with SHA-256.
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
