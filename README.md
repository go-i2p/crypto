# go-i2p/crypto

Comprehensive cryptography library for the I2P (Invisible Internet Project) anonymous networking ecosystem, factored out from the main router implementation. This package provides I2P-specific cryptographic implementations including symmetric encryption, asymmetric encryption, digital signatures, and hashing functions required for privacy-preserving communications and onion routing.

---

## Installation

Install the package using Go modules:

```bash
go get github.com/go-i2p/crypto
```

**Requirements:**
- Go 1.24.2 or later
- CGO_ENABLED=0 for static linking (recommended)

---

## Usage

### Basic Symmetric Encryption (AES)

```go
package main

import (
    "crypto/rand"
    "github.com/go-i2p/crypto/aes"
    "github.com/go-i2p/crypto/types"
)

func main() {
    // Generate key and IV
    key := make([]byte, 32) // AES-256
    iv := make([]byte, 16)  // AES block size
    rand.Read(key)
    rand.Read(iv)
    
    // Create symmetric key
    symmetricKey := &aes.AESSymmetricKey{
        Key: key,
        IV:  iv,
    }
    
    // Create encrypter and decrypter
    encrypter, _ := symmetricKey.NewEncrypter()
    decrypter, _ := symmetricKey.NewDecrypter()
    
    // Encrypt data
    plaintext := []byte("Hello, I2P!")
    ciphertext, _ := encrypter.Encrypt(plaintext)
    
    // Decrypt data
    decrypted, _ := decrypter.Decrypt(ciphertext)
}
```

### Asymmetric Encryption (Curve25519)

```go
package main

import (
    "github.com/go-i2p/crypto/curve25519"
    "github.com/go-i2p/crypto/types"
)

func main() {
    // Generate key pair
    pubKey, privKey, _ := curve25519.GenerateKeyPair()
    
    // Create encrypter and decrypter
    encrypter, _ := pubKey.NewEncrypter()
    decrypter, _ := privKey.NewDecrypter()
    
    // Encrypt data
    plaintext := []byte("Secret message")
    ciphertext, _ := encrypter.Encrypt(plaintext)
    
    // Decrypt data
    decrypted, _ := decrypter.Decrypt(ciphertext)
}
```

### Digital Signatures (Ed25519)

```go
package main

import (
    "github.com/go-i2p/crypto/ed25519"
    "github.com/go-i2p/crypto/types"
)

func main() {
    // Generate signing key
    privKey, _ := ed25519.GenerateEd25519Key()
    pubKey, _ := privKey.Public()
    
    // Create signer and verifier
    signer, _ := privKey.NewSigner()
    verifier, _ := pubKey.NewVerifier()
    
    // Sign data
    data := []byte("Document to sign")
    signature, _ := signer.Sign(data)
    
    // Verify signature
    err := verifier.Verify(data, signature)
    if err == nil {
        // Signature is valid
    }
}
```

---

## Features

- **Symmetric Encryption**
  - AES (128/192/256-bit) with CBC mode
  - ChaCha20 stream cipher

- **Asymmetric Encryption**
  - Curve25519 (X25519) key agreement
  - Ed25519 encryption support
  - RSA (2048/3072/4096-bit)
  - ElGamal encryption

- **Digital Signatures**
  - Ed25519 signatures
  - DSA (Digital Signature Algorithm)
  - ECDSA (P-256, P-384, P-521 curves)

- **Message Authentication**
  - HMAC (Hash-based Message Authentication Code)
  - HKDF (HMAC-based Key Derivation Function)

---

## Architecture

The package follows an interface-first design with core cryptographic interfaces defined in the `types/` package:

- `Encrypter` / `Decrypter` interfaces for encryption operations
- `Signer` / `Verifier` interfaces for signature operations
- `PublicEncryptionKey` / `PrivateEncryptionKey` for key management
- `SigningPublicKey` / `SigningPrivateKey` for signing keys

Each cryptographic algorithm is implemented in its own package with consistent error handling using the `github.com/samber/oops` library.

---

## Testing

Run the comprehensive test suite:

```bash
make test
```

The test suite includes table-driven tests for all cryptographic operations, testing edge cases like empty data, exact block sizes, and large datasets.

---

## License

MIT License - see LICENSE file for details.

Copyright (c) 2025 I2P For Go
