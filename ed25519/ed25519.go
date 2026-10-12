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
// See RFC 8032 for the Ed25519 specification:
// https://datatracker.ietf.org/doc/html/rfc8032
package ed25519
