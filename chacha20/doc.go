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
//   - This is the modern encryption standard for I2P tunnel and garlic
//     message encryption.
//
// See RFC 8439 for the ChaCha20-Poly1305 specification:
// https://datatracker.ietf.org/doc/html/rfc8439
package chacha20
