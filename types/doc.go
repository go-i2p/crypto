// Package types defines the shared interfaces used across the go-i2p/crypto
// library.
//
// These interfaces describe what an encryption or signing implementation must
// be able to do. By coding against these interfaces, the rest of the library
// can work with any algorithm (AES, ChaCha20, Ed25519, and so on) without
// caring which one is actually in use.
//
// # Encryption interfaces
//
//   - Encrypter: encrypts data.
//   - Decrypter: decrypts data.
//   - PublicEncryptionKey: a public key that can create an Encrypter.
//   - PrivateEncryptionKey: a private key that can create a Decrypter.
//
// # Signing interfaces
//
//   - Signer: creates a digital signature.
//   - Verifier: checks a digital signature.
//   - SigningPublicKey: a public key that can create a Verifier.
//   - SigningPrivateKey: a private key that can create a Signer.
package types
