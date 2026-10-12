// Package dsa provides DSA (Digital Signature Algorithm) signing for I2P.
//
// DSA is a digital signature algorithm. A signature proves that a message
// came from the holder of a private key and has not been altered. DSA signs
// a SHA-1 hash of the message and produces a 40-byte signature (20 bytes for
// the r value, 20 bytes for the s value).
//
// # How it works
//
//   - The signer hashes the data with SHA-1.
//   - The signer creates an (r, s) signature pair using its private key.
//   - A verifier checks the signature against the signer's public key.
//
// # Security notes
//
//   - DSA with SHA-1 is a legacy algorithm. New I2P code should prefer the
//     ed25519 or red25519 packages, which are faster and more secure.
//
// See the I2P cryptography overview for the role of DSA in I2P:
// https://i2p.net/en/docs/specs/cryptography/
package dsa
