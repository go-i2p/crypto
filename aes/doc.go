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
// # Relationship to the I2P specifications
//
// This package is a general-purpose AES-CBC helper. It is NOT an
// implementation of I2P's ElGamal/AES+SessionTags wire format
// (https://i2p.net/en/docs/specs/elgamal-aes/), and it is not the tunnel-layer
// cipher either (see the tunnel package for that). In particular the padding
// differs: this package uses standard PKCS#7 padding, whereas the I2P
// ElGamal/AES scheme pads with pseudorandom bytes and carries the real payload
// length in a separate field of the AES block. Do not use this package to
// interoperate with Java I2P's end-to-end encryption.
package aes
