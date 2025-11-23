# ChaCha20-Poly1305 AEAD

ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) for the I2P anonymous networking ecosystem.

## Overview

This package implements the IETF ChaCha20-Poly1305 AEAD construction as defined in RFC 8439, providing authenticated encryption that combines:

- **ChaCha20** stream cipher for confidentiality
- **Poly1305** MAC for authenticity
- **AEAD** construction for integrity of both ciphertext and associated data

## Features

- ✅ Authenticated encryption preventing message tampering
- ✅ High performance (faster than AES on systems without AES-NI)
- ✅ Constant-time implementation resistant to timing attacks  
- ✅ Support for additional authenticated data (AAD)
- ✅ Suitable for I2P tunnel and garlic message encryption

## Usage

### Basic Encryption/Decryption

```go
package main

import (
    "github.com/go-i2p/crypto/chacha20poly1305"
    "github.com/go-i2p/crypto/rand"
)

func main() {
    // Generate a random 32-byte key
    key, _ := chacha20poly1305.GenerateKey()
    
    // Create AEAD cipher
    aead, _ := chacha20poly1305.NewAEAD(key)
    
    // Generate a unique nonce for this message
    nonce, _ := chacha20poly1305.GenerateNonce()
    
    // Encrypt
    plaintext := []byte("Secret message")
    associatedData := []byte("public metadata")
    ciphertext, tag, _ := aead.Encrypt(plaintext, associatedData, nonce[:])
    
    // Decrypt and verify
    decrypted, err := aead.Decrypt(ciphertext, tag[:], associatedData, nonce[:])
    if err != nil {
        // Authentication failed - message was tampered with
        panic(err)
    }
    
    // Safe to use decrypted data
    println(string(decrypted))
}
```

### I2P Tunnel Encryption

```go
// Encrypt a tunnel message layer
func encryptTunnelLayer(plaintext []byte, layerKey [32]byte) ([]byte, [16]byte, error) {
    aead, _ := chacha20poly1305.NewAEAD(layerKey)
    nonce, _ := chacha20poly1305.GenerateNonce()
    
    // Use tunnel ID as associated data
    associatedData := tunnelID[:]
    
    return aead.Encrypt(plaintext, associatedData, nonce[:])
}
```

### Garlic Message Encryption

```go
// Encrypt a garlic message with session tag
func encryptGarlicMessage(plaintext, sessionTag []byte, sessionKey [32]byte) ([]byte, error) {
    aead, _ := chacha20poly1305.NewAEAD(sessionKey)
    nonce, _ := chacha20poly1305.GenerateNonce()
    
    // Session tag as associated data
    ciphertext, tag, err := aead.Encrypt(plaintext, sessionTag, nonce[:])
    if err != nil {
        return nil, err
    }
    
    // Package: nonce || ciphertext || tag
    result := make([]byte, 12+len(ciphertext)+16)
    copy(result[0:12], nonce[:])
    copy(result[12:], ciphertext)
    copy(result[12+len(ciphertext):], tag[:])
    
    return result, nil
}
```

## Security Considerations

### Nonce Uniqueness (Critical)

**Never reuse a nonce with the same key.** Nonce reuse breaks the authentication guarantee and can leak plaintext information.

```go
// ❌ WRONG - Reusing nonce
nonce, _ := chacha20poly1305.GenerateNonce()
aead.Encrypt(msg1, nil, nonce[:])  // First use - OK
aead.Encrypt(msg2, nil, nonce[:])  // DANGEROUS - Same nonce!

// ✅ CORRECT - New nonce for each message
nonce1, _ := chacha20poly1305.GenerateNonce()
aead.Encrypt(msg1, nil, nonce1[:])

nonce2, _ := chacha20poly1305.GenerateNonce()
aead.Encrypt(msg2, nil, nonce2[:])
```

### Key Management

- Use unique keys for different encryption contexts
- Derive encryption keys from shared secrets using HKDF
- Securely erase keys when no longer needed

### Authentication Tag Verification

Always check the error from `Decrypt()` before using the plaintext:

```go
plaintext, err := aead.Decrypt(ciphertext, tag, aad, nonce)
if err != nil {
    // Authentication failed - discard ciphertext
    return err
}
// Safe to use plaintext
```

## API Reference

### Constants

- `KeySize = 32` - ChaCha20-Poly1305 key size in bytes
- `NonceSize = 12` - Nonce size in bytes (IETF variant)
- `TagSize = 16` - Poly1305 authentication tag size in bytes

### Functions

#### `GenerateKey() ([32]byte, error)`

Generates a new random 32-byte key using a cryptographically secure RNG.

#### `GenerateNonce() ([12]byte, error)`

Generates a new random 12-byte nonce. Each nonce must be unique for a given key.

#### `NewAEAD(key [32]byte) (*AEAD, error)`

Creates a new ChaCha20-Poly1305 AEAD cipher with the given key.

### Methods

#### `Encrypt(plaintext, associatedData, nonce []byte) ([]byte, [16]byte, error)`

Encrypts plaintext with associated data. Returns ciphertext and authentication tag.

**Parameters:**
- `plaintext` - Data to encrypt
- `associatedData` - Additional data to authenticate (not encrypted)
- `nonce` - 12-byte unique nonce

**Returns:**
- `ciphertext` - Encrypted data (same length as plaintext)
- `tag` - 16-byte Poly1305 authentication tag
- `error` - Any error (e.g., invalid nonce size)

#### `Decrypt(ciphertext, tag, associatedData, nonce []byte) ([]byte, error)`

Decrypts ciphertext and verifies the authentication tag.

**Parameters:**
- `ciphertext` - Encrypted data
- `tag` - 16-byte Poly1305 authentication tag
- `associatedData` - Same associated data used during encryption
- `nonce` - Same 12-byte nonce used during encryption

**Returns:**
- `plaintext` - Decrypted data (only valid if error is nil)
- `error` - `ErrAuthenticationFailed` if verification fails

## Error Handling

The package defines these sentinel errors:

- `ErrInvalidKeySize` - Key is not 32 bytes
- `ErrInvalidNonceSize` - Nonce is not 12 bytes  
- `ErrAuthenticationFailed` - Tag verification failed (message tampered)
- `ErrInvalidCiphertext` - Ciphertext format is invalid

## Performance

ChaCha20-Poly1305 performance on modern x86-64 CPUs:

- **Encryption**: ~1.5 GB/s per core
- **Decryption**: ~1.5 GB/s per core

Performance is consistent regardless of CPU features, unlike AES which requires AES-NI for optimal speed.

## I2P Protocol Compliance

This implementation follows:

- RFC 8439 (ChaCha20-Poly1305 AEAD)
- I2P Proposal 144 (ECIES-X25519-AEAD-Ratchet)
- Modern I2P tunnel encryption specification

## Testing

Run tests:

```bash
go test -v
```

Run benchmarks:

```bash
go test -bench=. -benchmem
```

## License

MIT License - See LICENSE file for details
