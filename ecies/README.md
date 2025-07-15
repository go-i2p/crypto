# ecies
--
    import "github.com/go-i2p/crypto/ecies"

![ecies.svg](ecies.svg)

Package ecies constants for ECIES-X25519-AEAD-Ratchet encryption. Moved from:
ecies.go

Package ecies implements ECIES-X25519-AEAD-Ratchet encryption as specified in
I2P Proposal 144.

This package provides the modern I2P encryption scheme that replaces
ElGamal/AES+SessionTags. It implements ephemeral-static and ephemeral-ephemeral
Diffie-Hellman key agreement using X25519, combined with ChaCha20-Poly1305 AEAD
encryption.

The implementation follows I2P Proposal 144 specification:
https://geti2p.net/spec/proposals/144-ecies-x25519-aead-ratchet

Package ecies utility functions for ECIES-X25519-AEAD-Ratchet encryption. Moved
from: ecies.go

## Usage

```go
const (
	// PublicKeySize is the size of X25519 public keys in bytes
	PublicKeySize = 32
	// PrivateKeySize is the size of X25519 private keys in bytes
	PrivateKeySize = 32
	// NonceSize is the size of ChaCha20-Poly1305 nonces in bytes
	NonceSize = 12
	// TagSize is the size of Poly1305 authentication tags in bytes
	TagSize = 16
	// MaxPlaintextSize is the maximum size of plaintext data for encryption
	MaxPlaintextSize = 1024
)
```
Constants for ECIES-X25519 implementation Moved from: ecies.go

```go
var (
	ErrInvalidPublicKey    = oops.Errorf("invalid public key for ECIES-X25519")
	ErrInvalidPrivateKey   = oops.Errorf("invalid private key for ECIES-X25519")
	ErrDataTooBig          = oops.Errorf("data too large for ECIES-X25519 encryption")
	ErrInvalidCiphertext   = oops.Errorf("invalid ciphertext for ECIES-X25519 decryption")
	ErrDecryptionFailed    = oops.Errorf("ECIES-X25519 decryption failed")
	ErrKeyDerivationFailed = oops.Errorf("ECIES-X25519 key derivation failed")
)
```
Error constants for ECIES operations Moved from: ecies.go

#### func  DecryptECIESX25519

```go
func DecryptECIESX25519(recipientPrivKey, ciphertext []byte) ([]byte, error)
```
DecryptECIESX25519 decrypts ciphertext using ECIES-X25519 scheme. The private
key must be 32 bytes (X25519 private key). The ciphertext must be in the format:
[ephemeral_pubkey][nonce][aead_ciphertext] Moved from: ecies.go

#### func  EncryptECIESX25519

```go
func EncryptECIESX25519(recipientPubKey, plaintext []byte) ([]byte, error)
```
EncryptECIESX25519 encrypts plaintext using ECIES-X25519 scheme. This implements
the "New Session" message format from I2P Proposal 144. The recipient's public
key must be 32 bytes (X25519 public key). Returns ciphertext in the format:
[ephemeral_pubkey][nonce][aead_ciphertext] Moved from: ecies.go

#### func  GenerateKeyPair

```go
func GenerateKeyPair() ([]byte, []byte, error)
```
GenerateKeyPair generates a new X25519 key pair suitable for ECIES-X25519.
Returns (publicKey, privateKey, error) where keys are 32 bytes each. Moved from:
ecies.go



ecies 

github.com/go-i2p/crypto/ecies

[go-i2p template file](/template.md)
