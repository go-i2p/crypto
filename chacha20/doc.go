// Package chacha20 provides ChaCha20-Poly1305 symmetric encryption for I2P.
//
// ChaCha20-Poly1305 is an AEAD (Authenticated Encryption with Associated
// Data) cipher. It both encrypts your data and proves the data has not been
// tampered with. If even one bit of the ciphertext changes, decryption
// fails.
//
// # How it works
//
//   - A 32-byte key is shared between sender and receiver.
//   - A fresh 12-byte nonce is generated for every message.
//   - The output is the nonce followed by the ciphertext and an
//     authentication tag: [12-byte nonce][ciphertext + tag].
//
// # Security notes
//
//   - Never reuse a nonce with the same key. Reusing a nonce completely
//     breaks the security of the cipher.
//   - This is the modern encryption standard for I2P end-to-end (ECIES)
//     and transport (NTCP2/SSU2) encryption. I2P *tunnel layer* encryption
//     is AES-256-CBC type 0 only - see the tunnel package and
//     Tunnel-Creation-ECIES "Layer Encryption": "The only layer encryption
//     currently supported is type 0, which is AES."
//
// See RFC 8439 for the ChaCha20-Poly1305 specification:
// https://datatracker.ietf.org/doc/html/rfc8439
package chacha20
