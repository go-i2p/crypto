// Package aes provides AES (Advanced Encryption Standard) symmetric
// encryption for I2P.
//
// AES is a widely used block cipher that encrypts data in fixed-size blocks
// using a shared secret key. Both the sender and receiver must know the same
// key. This package implements AES in CBC (Cipher Block Chaining) mode, with
// and without PKCS#7 padding. The padded form is the general-purpose helper;
// note that I2P's legacy tunnel encryption (see the tunnel package) uses
// unpadded CBC over a fixed payload region rather than this package.
//
// # How it works
//
//   - A key (16, 24, or 32 bytes) is shared between sender and receiver.
//   - An IV (initialization vector) is used to make each encryption unique.
//   - Data is padded to a multiple of the 16-byte block size before
//     encryption.
//
// # Security notes
//
//   - AES-CBC is a legacy mode. New I2P code should prefer the
//     chacha20poly1305 package, which provides authenticated encryption.
//   - Never reuse an IV with the same key.
//
// See the I2P ElGamal/AES specification for the legacy tunnel encryption
// scheme: https://i2p.net/en/docs/specs/elgamal-aes/
package aes
