# Key Derivation Functions (KDF)

Consistent key derivation functions for the I2P cryptographic ecosystem.

## Overview

This package provides a unified API for deriving cryptographic keys from root secrets using HKDF (HMAC-based Key Derivation Function) as defined in RFC 5869. It ensures that keys are derived consistently across all I2P components with purpose-specific context strings.

## Features

- ✅ Standardized key derivation from root secrets
- ✅ Type-safe key purpose enumeration
- ✅ Multiple key derivation support
- ✅ Secure memory cleanup
- ✅ Compatible with ECIES, DH, and session keys

## Usage

### Basic Key Derivation

```go
package main

import (
    "github.com/go-i2p/crypto/kdf"
)

func main() {
    // Assume we have a root key from ECIES or DH key exchange
    var rootKey [32]byte
    // ... obtain root key ...
    
    // Create key derivation context
    kd := kdf.NewKeyDerivation(rootKey)
    defer kd.Zero() // Securely clear when done
    
    // Derive keys for different purposes
    tunnelKey, _ := kd.DeriveForPurpose(kdf.PurposeTunnelEncryption)
    garlicKey, _ := kd.DeriveForPurpose(kdf.PurposeGarlicEncryption)
    tagKey, _ := kd.DeriveForPurpose(kdf.PurposeSessionTag)
}
```

### Session Key Derivation

```go
// Derive standard set of keys for I2P session initialization
kd := kdf.NewKeyDerivation(eciesSharedSecret)

rootKey, symKey, tagKey, err := kd.DeriveSessionKeys()
if err != nil {
    return err
}

// Use keys to initialize ratchets
dhRatchet := ratchet.NewDHRatchet(rootKey, ourPriv, theirPub)
symRatchet := ratchet.NewSymmetricRatchet(symKey)
tagRatchet := ratchet.NewTagRatchet(tagKey)
```

### Multiple Related Keys

```go
// Derive multiple keys for complex encryption schemes
kd := kdf.NewKeyDerivation(masterSecret)

keys, _ := kd.DeriveKeys([]byte("Tunnel-Layer-42"), 3)
encryptKey := keys[0]  // For encryption
macKey := keys[1]      // For MAC
ivKey := keys[2]       // For IV generation
```

### Custom Key Derivation

```go
// Derive keys with custom context strings
kd := kdf.NewKeyDerivation(rootKey)

// Application-specific key
appKey, _ := kd.DeriveWithInfo("MyApp-Extension-v1")

// Session-specific key
sessionKey, _ := kd.DeriveWithInfo(fmt.Sprintf("Session-%s", sessionID))
```

## Standard Key Purposes

The package defines standard purposes for I2P protocol components:

| Purpose | Use Case | Info String |
|---------|----------|-------------|
| `PurposeTunnelEncryption` | Tunnel layer encryption | `I2P-Tunnel-Encryption-v1` |
| `PurposeGarlicEncryption` | Garlic message encryption | `I2P-Garlic-Encryption-v1` |
| `PurposeSessionTag` | Session tag generation | `I2P-Session-Tag-v1` |
| `PurposeRatchetChain` | Ratchet chain keys | `I2P-Ratchet-Chain-v1` |
| `PurposeIVGeneration` | IV/nonce generation | `I2P-IV-Generation-v1` |
| `PurposeMessageKey` | Per-message encryption | `I2P-Message-Key-v1` |
| `PurposeHandshake` | Handshake keys | `I2P-Handshake-v1` |

## API Reference

### Types

#### `KeyPurpose`

Enumeration of standard key purposes for I2P components.

#### `KeyDerivation`

Main type for deriving keys from a root secret.

### Functions

#### `NewKeyDerivation(rootKey [32]byte) *KeyDerivation`

Creates a new key derivation context from a 32-byte root key.

### Methods

#### `DeriveForPurpose(purpose KeyPurpose) ([32]byte, error)`

Derives a single 32-byte key using a standard I2P purpose.

#### `DeriveWithInfo(info string) ([32]byte, error)`

Derives a single 32-byte key using a custom info string.

#### `DeriveKeys(info []byte, count int) ([][32]byte, error)`

Derives multiple 32-byte keys from the same context.

#### `DeriveSessionKeys() (rootKey, symKey, tagKey [32]byte, err error)`

Convenience method to derive the standard set of session keys.

#### `Zero()`

Securely clears the root key from memory.

## Security Considerations

### Root Key Requirements

- Root keys should be high-entropy secrets (32 bytes minimum)
- Use cryptographically secure random sources
- Derive from established key exchange protocols (ECIES, DH)
- Never reuse root keys across different contexts

### Info String Best Practices

- Use standard purposes when available for consistency
- Custom info strings should be unique per use case
- Include version numbers for protocol evolution
- Prefix with application/component identifier

### Key Uniqueness

Keys derived with different purposes or info strings are cryptographically independent:

```go
kd := kdf.NewKeyDerivation(rootKey)

key1, _ := kd.DeriveForPurpose(kdf.PurposeTunnelEncryption)
key2, _ := kd.DeriveForPurpose(kdf.PurposeGarlicEncryption)

// key1 and key2 are completely independent
```

## I2P Protocol Integration

This package is designed for:

- **ECIES-X25519-AEAD-Ratchet**: Deriving session keys from shared secrets
- **Tunnel Building**: Deriving layer-specific encryption keys
- **Garlic Messages**: Deriving message-specific keys
- **Session Management**: Consistent key derivation across session types

## Testing

Run tests:

```bash
go test -v
```

## License

MIT License - See LICENSE file for details
