// Package tunnel implements I2P-specific tunnel cryptography for secure data transmission.
//
// This package provides cryptographic primitives for I2P tunnel layer encryption and decryption,
// supporting both modern ECIES-X25519 encryption and legacy AES-256-CBC encryption schemes.
// The interface-based design enables seamless switching between encryption types based on
// router capabilities and network compatibility requirements.
//
// # Encryption Types
//
// Modern ECIES-X25519 (Type 1) - RECOMMENDED:
//   - X25519 elliptic curve Diffie-Hellman key agreement
//   - ChaCha20-Poly1305 authenticated encryption with associated data (AEAD)
//   - 218-byte tunnel records (78% smaller than AES)
//   - Significant bandwidth savings and improved security
//   - Default for new tunnel builds with I2P router version 0.9.51+
//
// Legacy AES-256-CBC (Type 0) - COMPATIBILITY ONLY:
//   - Dual-layer AES-256 encryption with separate layer and IV keys
//   - 1028-byte fixed-size tunnel messages (16-byte IV + 1008-byte payload)
//   - CBC mode encryption with IV-based randomization
//   - Required for backward compatibility with older I2P routers
package tunnel
