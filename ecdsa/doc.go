// Package ecdsa provides ECDSA (Elliptic Curve Digital Signature Algorithm)
// signing for I2P.
//
// ECDSA is a digital signature algorithm built on elliptic curves. It is
// faster and uses shorter keys than the older DSA algorithm while providing
// equivalent security. This package supports the NIST P-256, P-384, and
// P-521 curves.
//
// # How it works
//
//   - The signer hashes the data with a curve-appropriate hash: SHA-256 for
//     P-256, SHA-384 for P-384, and SHA-512 for P-521.
//   - The signer creates an (r, s) signature pair using its private key.
//   - A verifier checks the signature against the signer's public key.
//
// # Key construction
//
// Always use the provided constructors (for example
// NewECP256PrivateKey) to create keys. Constructing a key type directly with
// a zero value produces an invalid key; operations on it return an error
// rather than panicking.
//
// See the I2P cryptography overview for the role of ECDSA in I2P:
// https://i2p.net/en/docs/specs/cryptography/
package ecdsa
