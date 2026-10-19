// Package red25519 implements the Red25519 (RedDSA-SHA512-Ed25519, signature
// type 11) digital signature scheme for I2P.
//
// Red25519 is a Schnorr signature scheme over Ed25519's curve that supports
// additive key re-randomization ("blinding"). It exists for one purpose:
// encrypted LeaseSets. An encrypted LeaseSet2 published to a floodfill must be
// authenticated without revealing which Destination it belongs to, so the
// Destination's signing keys are blinded; floodfills verify with the blinded key
// and the Destination can prove the floodfill's copy is authentic. See
// https://i2p.net/en/docs/specs/red25519/ ("Red25519 Signature Scheme") and
// https://i2p.net/en/docs/specs/encryptedleaseset/ (Proposal 123).
// cryptography.md §Signatures lists RedDSA-SHA512-Ed25519 "For encrypted
// leasesets. Supported as of release 0.9.39".
//
// # How it differs from Ed25519
//
// Red25519 is NOT Ed25519 with a different name. Five things change the bytes on
// the wire, all specified in red25519.md:
//
//   - The hash is domain-separated: H(x) := SHA-512("I2P_Red25519H(x)" || x).
//   - Messages are length-prefixed, len_u16(M) || M little-endian, because
//     SHA-512 alone is "not secure against length extension attacks"; messages
//     are capped at 65534 bytes.
//   - Signing draws 80 random bytes (T) for the nonce, so "every Red25519
//     signature is different, even when signing the same data with the same
//     key". Deterministic signing would let an observer link two sightings of a
//     blinded Destination, destroying the unlinkability the scheme provides.
//   - Private keys are scalars reduced mod L, 32 bytes, never "clamped" the way
//     Ed25519 derives them.
//   - Verification multiplies by the cofactor (8) before the identity check.
//
// # Blinding is additive
//
// Both keys are re-randomized with the same scalar alpha by ADDITION:
//
//	A' = vk + [alpha] B
//	a' = (a + alpha) mod L
//
// which is what makes the spec's required invariant hold:
//
//	RANDOMIZE_PUBLIC(vk, alpha) == DERIVE_PUBLIC(RANDOMIZE_PRIVATE(sk, alpha))
//
// [BlindPublicKey] and [BlindPrivateKey] implement exactly this and agree with
// [github.com/go-i2p/crypto/ed25519]'s blinding for the same alpha. Do not mix
// the two key operations with a multiplicative scheme (A' = [b]A, a' = a*b mod l):
// it satisfies a different invariant, so blinding the private key one way and the
// public key the other produces a keypair whose signatures never verify.
//
// The blinding factor alpha comes from
// [github.com/go-i2p/crypto/kdf].DeriveBlindingFactorI2P, which implements
// encryptedleaseset.md GENERATE_ALPHA.
//
// # Converting an Ed25519 Destination
//
// Ed25519 keys may be converted one-way so an existing Destination can be
// blinded: [ConvertEd25519PrivateKey] (CONVERT_ED25519_PRIVATE) and
// [ConvertEd25519PublicKey] (CONVERT_ED25519_PUBLIC). red25519.md §Security
// implications notes the converted key distribution is slightly weaker than
// GENERATE_PRIVATE; "Users who are concerned about this security reduction should
// use Red25519 as the sigtype for their Destinations instead of Ed25519."
//
// # Interoperability
//
// [TestRed25519SpecVectors] (in spec_vectors_test.go) checks this implementation
// against all ten test vectors published in red25519.md §Test vectors, generated
// by the reference implementation: the conversions, DERIVE_PUBLIC, both
// re-randomization functions, the blinding invariant, and VERIFY of signatures
// this code never produced.
//
// Note: Red25519 is for signatures only - use the curve25519 package for
// encryption operations.
package red25519
