// Package tunnel implements the cryptography used to protect I2P tunnel
// messages, the small packets that carry data between routers.
//
// # What this package does
//
// When I2P routers send data to each other, the data travels inside tunnel
// messages. This package encrypts and decrypts those messages. It supports
// two schemes, selected by a local encryption-type value:
//
//   - ECIES-X25519 (TunnelEncryptionECIES, value 1): the modern scheme. It
//     uses X25519 key agreement and ChaCha20-Poly1305 authenticated
//     encryption. This is the recommended default for new tunnels.
//   - AES-256-CBC (TunnelEncryptionAES, value 0): the legacy scheme. It uses
//     two separate AES-256 keys (one for the payload, one for the IV) in CBC
//     mode, with a fixed 1028-byte message layout. It exists only for
//     compatibility with older routers.
//
// Note that these local values (0 and 1) are an internal choice of this
// package. They are not the same as the "crypto type" field in the I2P
// LeaseSet2 (LS2) records, where ECIES-X25519 is identified by crypto type 4.
//
// # How it fits the I2P specification
//
// The ECIES-X25519 tunnel scheme follows the I2P ECIES-X25519-AEAD-Ratchet
// specification (Proposal 144), supported by I2P routers as of version
// 0.9.46. The legacy AES-256-CBC scheme follows the older ElGamal/AES+
// SessionTags specification.
//
// See the official specifications:
//   - ECIES-X25519-AEAD-Ratchet: https://i2p.net/en/docs/specs/ecies/
//   - ElGamal/AES+SessionTags: https://i2p.net/en/docs/specs/elgamal-aes/
//
// # Message layout
//
// A tunnel message is a fixed 1028-byte block. In the legacy AES scheme the
// first 16 bytes are the initialization vector (IV) and the remaining 1008
// bytes are the encrypted payload. The ECIES scheme produces a compact
// ciphertext of [ephemeral public key][nonce][AEAD ciphertext].
package tunnel
