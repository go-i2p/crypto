package chacha20

// ChaCha20Key represents a 256-bit key for ChaCha20 encryption/decryption operations.
// Moved from: chacha20.go
type ChaCha20Key [KeySize]byte

// ChaCha20Nonce represents a 96-bit nonce for ChaCha20-Poly1305 AEAD operations.
// Moved from: chacha20.go
type ChaCha20Nonce [NonceSize]byte
