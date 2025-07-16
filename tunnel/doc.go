// Package tunnel implements I2P-specific tunnel cryptography for secure data transmission.
//
// This package provides cryptographic primitives for I2P tunnel layer encryption and decryption,
// implementing the dual-layer encryption scheme used in I2P network tunnels. The tunnel cryptography
// uses AES-256 in CBC mode with separate layer and IV encryption keys to provide security against
// traffic analysis and ensure forward secrecy within the I2P anonymous network.
//
// The implementation follows I2P's tunnel message format with 1028-byte fixed-size messages,
// where the first 16 bytes serve as the initialization vector and the remaining 1008 bytes
// contain the encrypted payload data.
//
// Key features:
//   - Dual-layer AES encryption with separate keys for layer and IV operations
//   - Fixed 1028-byte tunnel message format for network compatibility
//   - CBC mode encryption with IV-based randomization
//   - Secure in-place encryption/decryption operations
// package for i2p specific crpytography
package tunnel
