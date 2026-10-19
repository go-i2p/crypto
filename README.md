# go-i2p/crypto

Cryptography building blocks for I2P (Invisible Internet Project), the
anonymous network. I2P hides who you are talking to by routing messages
through a series of relays. This library provides the encryption, signing,
and key-derivation primitives that make that routing private.

It was factored out of the main router so that the crypto can be used and
audited on its own.

## Scope

This package contains **crypto primitives and interfaces only** — not full
protocol implementations. It is the lowest-level component in the `go-i2p`
namespace, so it must not depend on the higher-level packages:

 - [go-i2p/common](https://github.com/go-i2p/common): I2P common data structures
 - [go-i2p/noise](https://github.com/go-i2p/noise): Noise handshake implementations
 - [go-i2p/go-noise](https://github.com/go-i2p/go-noise): Noise handshake modifications and router interface
 - [go-i2p/go-i2p](https://github.com/go-i2p/go-i2p): I2P router implementation

---

## How the pieces fit together

I2P needs three kinds of cryptography. Here is how they build on each other,
from the simplest idea to the full scheme:

1. **Keys.** Every scheme starts with a key pair. A *public* key can be shared
   openly; a *private* key must be kept secret. The `ed25519` and `curve25519`
   packages generate these.

2. **Shared secrets.** Two parties who never met can agree on a secret by
   combining their keys. This is called *key agreement* (X25519 in the
   `curve25519` package). The `hkdf` and `kdf` packages then stretch that
   shared secret into the specific keys each part of the protocol needs.

3. **Encryption.** With a key in hand, data is encrypted. The modern choice is
   ChaCha20-Poly1305 (`chacha20poly1305`), which also detects tampering.

4. **Forward secrecy.** The `ratchet` package keeps rotating the keys as
   messages flow, so compromising one key does not expose past messages.

5. **The full scheme.** The `ecies` package ties these together into
   ECIES-X25519-AEAD-Ratchet, the current I2P *end-to-end* (destination-to-
   destination) encryption standard.

   Keep two different things called "tunnel encryption" separate. ECIES-X25519
   **is** the deployed standard for *building* tunnels — per the Low-level
   Cryptography spec, "X25519 tunnel creation has replaced ElGamal tunnel
   creation" — and the `tunnel` package implements that spec's build-record
   key schedule and reply/layer KDFs ([tunnel.BuildNoiseState](tunnel/buildkeys.go),
   [tunnel.EncryptBuildRequest](tunnel/buildkeys.go)). Separately, the
   *layer* encryption of each 1028-byte tunnel message is AES-256-CBC, which is
   the only layer encryption type any specification defines. The `tunnel`
   package's `TunnelEncryptionECIES` value is neither of those: it is an
   experimental wrapper around the end-to-end one-time format and does not
   interoperate.

Start with the package docs on [pkg.go.dev](https://pkg.go.dev/github.com/go-i2p/crypto)
for details on each piece.

---

## Installation

Install the package using Go modules:

```bash
go get github.com/go-i2p/crypto
```

**Requirements:**
- Go 1.26.8 or later
- CGO_ENABLED=0 for static linking (recommended)

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
    "github.com/go-i2p/crypto/chacha20poly1305"
    "github.com/go-i2p/crypto/ratchet"
)

func main() {
    // Inputs from a prior ECIES key exchange:
    //   eciesSharedSecret, ourEphemeralPrivKey, theirPublicKey ([32]byte each)
    var eciesSharedSecret, ourEphemeralPrivKey, theirPublicKey [32]byte
    plaintext := []byte("Hello, I2P!")

    session, err := ratchet.NewSessionFromECIES(
        eciesSharedSecret,
        ourEphemeralPrivKey,
        theirPublicKey,
    )
    if err != nil {
        panic(err)
    }
    defer session.Zero()

    // Derive the message key, session tag, and spec counter nonce (advances the
    // ratchets). EncryptMessage does not encrypt the payload itself.
    messageKey, sessionTag, nonce, _ := session.EncryptMessage(plaintext)

    // Use the message key and the returned nonce with a ChaCha20-Poly1305 AEAD.
    // Per the ECIES spec the session tag is the associated data and the nonce is
    // the message number - do not generate a random nonce here.
    aead, _ := chacha20poly1305.NewAEAD(messageKey)
    ciphertext, authTag, _ := aead.Encrypt(plaintext, sessionTag[:], nonce[:])
    _, _ = ciphertext, authTag
}
```

### Consistent Key Derivation

```go
package main

import (
    "github.com/go-i2p/crypto/kdf"
)

func main() {
    // StandardHKDF is the canonical RFC 5869 HKDF-SHA256 wrapper. The I2P ECIES
    // spec defines HKDF(salt, ikm, info, n) with a 32-byte salt, so pass the
    // chain key as salt and use the spec's own info string.
    salt := make([]byte, 32)   // e.g. a chain key or shared secret
    ikm := make([]byte, 32)    // zero-length is allowed (the spec's ZEROLEN)

    keydata, err := kdf.StandardHKDF(salt, ikm, []byte("SymmetricRatchet"), 64)
    if err != nil {
        panic(err)
    }

    nextChainKey := keydata[0:32]
    messageKey := keydata[32:64]
    _, _ = nextChainKey, messageKey

    // For ratcheted ECIES sessions, prefer the spec KDFs already wired up in
    // crypto/ratchet rather than calling HKDF by hand:
    //   ratchet.NewSymmetricRatchet / NewTagRatchet / DH_INITIALIZEFull
}
```

### Basic Symmetric Encryption (AES)

```go
package main

import (
    "github.com/go-i2p/crypto/rand"
    "github.com/go-i2p/crypto/aes"
)

func main() {
    // Generate key and IV
    key := make([]byte, 32) // AES-256
    iv := make([]byte, 16)  // AES block size
    rand.Read(key)
    rand.Read(iv)
    
    // Create symmetric key (always use the validating constructor; it rejects
    // wrong-length keys and IVs and copies the input. Note it validates sizes
    // only - an all-zero key passed via a struct literal is still accepted, so
    // do not construct AESSymmetricKey that way)
    symmetricKey, _ := aes.NewAES256Key(key, iv)
    defer symmetricKey.Zero()
    
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

### ChaCha20-Poly1305 AEAD (via the chacha20 package)

```go
package main

import (
    "github.com/go-i2p/crypto/chacha20"
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

### Asymmetric Encryption (ElGamal — legacy)

> **Deprecated.** ElGamal is the original I2P encryption scheme. It is kept
> only for compatibility with older routers and for decrypting legacy data.
> New code should use the `ecies` package (ECIES-X25519-AEAD-Ratchet).

```go
package main

import (
    "github.com/go-i2p/crypto/elg"
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
    "github.com/go-i2p/crypto/hmac"
)

func main() {
    // Generate HMAC key (always use the constructors; a zero-value HMACKey is
    // cryptographically invalid and rejected by the hmac package docs)
    key, _ := hmac.GenerateHMACKey()
    defer key.Zero()

    // Data to authenticate
    data := []byte("Authenticate this message")

    // Compute HMAC-SHA256 digest
    digest := hmac.I2PHMAC(data, *key)

    // Use digest for authentication or verification
}
```

### Digital Signatures (Ed25519)

```go
package main

import (
    "github.com/go-i2p/crypto/ed25519"
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
  - ChaCha20-Poly1305 AEAD (authenticated encryption) — the modern standard
  - ChaCha20-Poly1305 via the `chacha20` package (AEAD, nonce-prefixed output)
  - AES (128/192/256-bit) with CBC mode — legacy

- **Asymmetric Encryption**
  - ECIES-X25519-AEAD-Ratchet with a unified Session API — the modern standard
    for end-to-end encryption. Coverage is partial: the one-time (§1d) format
    and the data-phase KDFs are implemented, the New Session Reply (§1g),
    payload block format (§5) and full bound-session handshake are not, so a
    session created here will not interoperate with a Java router. See the
    `ecies` and `ratchet` package docs.
  - Curve25519 (X25519) key agreement
  - ElGamal — legacy, kept for compatibility with older routers

- **Digital Signatures**
  - Ed25519 signatures — the standard I2P signature type
  - Ed25519ph (pre-hashed variant)
  - ECDSA (P-256, P-384, P-521 curves)
  - DSA (Digital Signature Algorithm) — legacy
  - RSA (2048/3072/4096-bit) — legacy

- **Message Authentication**
  - HMAC (Hash-based Message Authentication Code)
  - HKDF (HMAC-based Key Derivation Function)
  - Unified KDF utilities for consistent key derivation

- **Key Management**
  - Concrete key generation APIs (no type assertions needed)
  - Secure memory cleanup with `Zero()` methods
  - Forward secrecy with ratcheting

---

## Logging

All packages use structured logging via [`github.com/go-i2p/logger`](https://github.com/go-i2p/logger). Every log call includes `"pkg"` and `"func"` fields for precise filtering and tracing:

```go
log.WithFields(logger.Fields{
    "pkg":  "curve25519",
    "func": "Curve25519PublicKey.NewEncrypter",
}).Debug("Creating new encrypter")
```

### Enabling Debug Output

Set the `DEBUG_I2P` environment variable to enable debug-level log output:

```bash
DEBUG_I2P=debug go test ./...
```

To treat warnings as fatal errors (useful for CI):

```bash
WARNFAIL_I2P=true DEBUG_I2P=debug go test ./...
```

### Filtering Logs

Because every log call carries structured `pkg` and `func` fields, you can filter output programmatically by package or function name to isolate specific subsystems during debugging.

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

Run the test suite:

```bash
go test ./...
```

The test suite includes table-driven tests for the cryptographic operations in most packages, testing edge cases like empty data, exact block sizes, and large datasets. The `argon2`, `common`, `siphash`, and `types` packages currently have no test files.

---

## License

MIT License - see LICENSE file for details.

Copyright (c) 2025 I2P For Go
