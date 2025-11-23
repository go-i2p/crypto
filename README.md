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

## Recent API Improvements

🎉 **Version 2.0** includes major API improvements based on production usage patterns:

- ✅ **Concrete Key Generation**: New `GenerateEd25519KeyPair()` and `GenerateX25519KeyPair()` return concrete types
- ✅ **ChaCha20-Poly1305 AEAD**: Dedicated authenticated encryption package for I2P tunnel and garlic messages
- ✅ **Unified Session API**: Single `Session` type manages DH, symmetric, and tag ratchets
- ✅ **KDF Utilities**: Consistent key derivation with `kdf.KeyDerivation` for all I2P components
- ✅ **Better Error Handling**: Standardized sentinel errors across all packages

See [AUDIT.md](AUDIT.md) for detailed improvement rationale.

---

## Usage

### Modern Key Generation (Recommended)

```go
package main

import (
    "github.com/go-i2p/crypto/ed25519"
    "github.com/go-i2p/crypto/curve25519"
)

func main() {
    // Generate Ed25519 signing keys - returns concrete types
    sigPubKey, sigPrivKey, err := ed25519.GenerateEd25519KeyPair()
    if err != nil {
        panic(err)
    }
    defer sigPrivKey.Zero() // Securely clear private key
    
    // Generate X25519 encryption keys - returns concrete types
    encPubKey, encPrivKey, err := curve25519.GenerateX25519KeyPair()
    if err != nil {
        panic(err)
    }
    defer encPrivKey.Zero()
    
    // Use keys directly without type assertions
    signer, _ := sigPrivKey.NewSigner()
    signature, _ := signer.Sign([]byte("message"))
}
```

### Authenticated Encryption (ChaCha20-Poly1305 AEAD)

```go
package main

import (
    "github.com/go-i2p/crypto/chacha20poly1305"
)

func main() {
    // Generate key and nonce
    key, _ := chacha20poly1305.GenerateKey()
    nonce, _ := chacha20poly1305.GenerateNonce()
    
    // Create AEAD cipher
    aead, _ := chacha20poly1305.NewAEAD(key)
    
    // Encrypt with authentication
    plaintext := []byte("Secret message")
    associatedData := []byte("public metadata")
    ciphertext, tag, _ := aead.Encrypt(plaintext, associatedData, nonce[:])
    
    // Decrypt and verify
    decrypted, err := aead.Decrypt(ciphertext, tag[:], associatedData, nonce[:])
    if err != nil {
        // Authentication failed - message was tampered with
        panic(err)
    }
}
```

### Unified Session Management

```go
package main

import (
    "github.com/go-i2p/crypto/ratchet"
)

func main() {
    // After ECIES key exchange
    session, err := ratchet.NewSessionFromECIES(
        eciesSharedSecret,
        ourEphemeralPrivKey,
        theirPublicKey,
    )
    if err != nil {
        panic(err)
    }
    defer session.Zero()
    
    // Encrypt message (handles all ratchet operations)
    messageKey, sessionTag, _ := session.EncryptMessage(plaintext)
    
    // Use message key with AEAD
    aead, _ := chacha20poly1305.NewAEAD(messageKey)
    ciphertext, authTag, _ := aead.Encrypt(plaintext, sessionTag[:], nonce)
}
```

### Consistent Key Derivation

```go
package main

import (
    "github.com/go-i2p/crypto/kdf"
)

func main() {
    // Derive keys from root secret
    kd := kdf.NewKeyDerivation(rootSecret)
    defer kd.Zero()
    
    // Derive purpose-specific keys
    tunnelKey, _ := kd.DeriveForPurpose(kdf.PurposeTunnelEncryption)
    garlicKey, _ := kd.DeriveForPurpose(kdf.PurposeGarlicEncryption)
    
    // Or derive session keys in one call
    rootKey, symKey, tagKey, _ := kd.DeriveSessionKeys()
}
```

### Basic Symmetric Encryption (AES)

```go
package main

import (
    "github.com/go-i2p/crypto/rand"
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

### Stream Cipher Encryption (ChaCha20)

```go
package main

import (
    "github.com/go-i2p/crypto/chacha20"
    "github.com/go-i2p/crypto/types"
)

func main() {
    // Generate ChaCha20 key
    key, _ := chacha20.GenerateKey()
    
    // Create encrypter and decrypter
    encrypter, _ := key.NewEncrypter()
    decrypter, _ := key.NewDecrypter()
    
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

### Asymmetric Encryption (ElGamal)

```go
package main

import (
    "github.com/go-i2p/crypto/elg"
    "github.com/go-i2p/crypto/types"
)

func main() {
    // Generate ElGamal key pair
    pubKey, privKey, _ := elg.GenerateKeyPair()

    // Create encrypter and decrypter
    encrypter, _ := pubKey.NewEncrypter()
    decrypter, _ := privKey.NewDecrypter()

    // Encrypt data
    plaintext := []byte("Confidential message")
    ciphertext, _ := encrypter.Encrypt(plaintext)

    // Decrypt data
    decrypted, _ := decrypter.Decrypt(ciphertext)
}
```


### Message Authentication (HMAC)

```go
package main

import (
    "github.com/go-i2p/crypto/rand"
    "github.com/go-i2p/crypto/hmac"
)

func main() {
    // Generate HMAC key
    var key hmac.HMACKey
    rand.Read(key[:])

    // Data to authenticate
    data := []byte("Authenticate this message")

    // Compute HMAC-SHA256 digest
    digest := hmac.I2PHMAC(data, key)

    // Use digest for authentication or verification
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
  - **ChaCha20-Poly1305 AEAD** (authenticated encryption) ✨ NEW

- **Asymmetric Encryption**
  - Curve25519 (X25519) key agreement
  - RSA (2048/3072/4096-bit)
  - ElGamal encryption
  - **ECIES-X25519-AEAD-Ratchet** with unified Session API ✨ NEW

- **Digital Signatures**
  - Ed25519 signatures
  - DSA (Digital Signature Algorithm)
  - ECDSA (P-256, P-384, P-521 curves)

- **Message Authentication**
  - HMAC (Hash-based Message Authentication Code)
  - HKDF (HMAC-based Key Derivation Function)
  - **Unified KDF utilities** for consistent key derivation ✨ NEW

- **Key Management**
  - **Concrete key generation APIs** (no type assertions needed) ✨ NEW
  - Secure memory cleanup with `Zero()` methods
  - Forward secrecy with ratcheting

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
