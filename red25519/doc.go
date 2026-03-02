// Package red25519 provides Red25519 (RedDSA) digital signature functionality for I2P cryptographic operations.
//
// Red25519 extends standard Ed25519 with key blinding: a 32-byte scalar blinding factor
// is multiplied into both the private and public key, producing a new keypair that is
// unlinkable to the original yet fully functional for signing and verification.
// This is used in the I2P network for destination blinding (encrypted leasesets, etc.).
//
// This package wraps github.com/go-i2p/red25519 to implement the types.SigningPublicKey,
// types.SigningPrivateKey, types.Signer, and types.Verifier interfaces used throughout
// the go-i2p/crypto library.
//
// The API mirrors crypto/ed25519 with additional blinding primitives:
//   - Unblinded signatures are byte-identical to crypto/ed25519
//   - Key blinding produces unlinkable keypairs via scalar multiplication
//   - Verify rejects small-order public keys for defense against forgery
//
// Note: Red25519 is for signatures only - use curve25519 package for encryption operations.
package red25519
