package chacha20

// ChaCha20Key represents a 256-bit key for ChaCha20 encryption/decryption operations.
//
// ⚠️ CRITICAL SECURITY WARNING:
// Do NOT construct ChaCha20Key directly using var or struct literals.
// Zero-value construction results in an all-zero key which is cryptographically weak.
//
// WRONG - Cryptographically weak:
//
//	var key ChaCha20Key              // All zeros - predictable!
//	key := ChaCha20Key{}             // All zeros - predictable!
//
// CORRECT - Use constructors:
//
//	key, err := chacha20.NewChaCha20Key(keyBytes)
//	if err != nil {
//	    return err
//	}
//
// Or for random generation:
//
//	key, err := chacha20.GenerateKey()
//
// Moved from: chacha20.go
type ChaCha20Key [KeySize]byte

// ChaCha20Nonce represents a 96-bit nonce for ChaCha20-Poly1305 AEAD operations.
// Moved from: chacha20.go
type ChaCha20Nonce [NonceSize]byte
