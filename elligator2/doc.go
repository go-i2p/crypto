// Package elligator2 implements Elligator2 encoding for Curve25519 public keys.
//
// Elligator2 encoding makes Curve25519 ephemeral public keys indistinguishable from
// random data, preventing traffic analysis attacks. This is used in protocols like
// I2P's ECIES-X25519-AEAD-Ratchet for New Session messages.
//
// Specification: https://elligator.cr.yp.to/elligator-20130828.pdf
//
// # Relationship to the I2P ECIES specification
//
// I2P uses this encoding for the ephemeral public key of an ECIES-X25519-AEAD
// message. The governing section is ECIES-X25519-AEAD-Ratchet §2a "Elligator 2
// Function" at https://i2p.net/en/docs/specs/ecies/ , which specifies the
// Curve25519 variant, the two random high bits, and the decode behavior, and
// whose Notes state the key-generation cost:
//
//	"the key generation time is unbounded with an exponential distribution, as
//	the generator must keep retrying until a suitable key pair is found."
//
// §2 gives the surrounding primitive: "DH Function: X25519 ... as specified in
// RFC-7748". [GenerateEncodedKeyPair] documents where and why this
// implementation bounds that retry loop.
//
// Key properties:
//   - Encodes Curve25519 public keys as 32 random-looking bytes
//   - Approximately 50% of Curve25519 private keys produce suitable public keys
//   - Constant-time operations to prevent timing attacks
//   - The representative-to-public-key map is deliberately many-to-one: the
//     top 2 bits of the 32-byte representative are random padding masked off on
//     decode, so 4 representatives map to each curve point.
//
// This implementation is based on the reference implementation by Adam Langley
// and the Tor Project's implementation.
package elligator2
