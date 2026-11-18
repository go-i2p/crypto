// Package aes provides AES (Advanced Encryption Standard) symmetric
// encryption for I2P.
//
// AES is a widely used block cipher that encrypts data in fixed-size blocks
// using a shared secret key. Both the sender and receiver must know the same
// key. This package implements AES in CBC (Cipher Block Chaining) mode without
// padding: the caller supplies data whose length is a multiple of the 16-byte
// block size. This matches how I2P uses AES-CBC (unpadded, over fixed-size
// payload regions, e.g. the tunnel and ElGamal/AES session layers) rather than
// the PKCS#7-style padding common in general-purpose crypto libraries.
//
// # How it works
//
//   - A key (16, 24, or 32 bytes) is shared between sender and receiver.
//   - An IV (initialization vector) is used to make each encryption unique.
//   - Data must already be a multiple of the 16-byte block size; no padding is
//     applied or stripped.
//
// # Security notes
//
//   - AES-CBC is a legacy mode. New I2P code should prefer the
//     chacha20poly1305 package, which provides authenticated encryption.
//   - Never reuse an IV with the same key.
//
// # Relationship to the I2P specifications
//
// This package is a general-purpose AES-CBC helper. It is NOT an
// implementation of I2P's ElGamal/AES+SessionTags wire format
// (https://i2p.net/en/docs/specs/elgamal-aes/), and it is not the tunnel-layer
// cipher either (see the tunnel package for that). In particular it applies no
// padding, whereas the I2P ElGamal/AES scheme pads with pseudorandom bytes
// (RFC-2313 block type 02) and carries the real payload length in a separate
// field of the AES block. Do not use this package to interoperate with Java
// I2P's end-to-end encryption.
package aes
