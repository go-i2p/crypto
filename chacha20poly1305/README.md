# chacha20poly1305
--
    import "github.com/go-i2p/crypto/chacha20poly1305"

![chacha20poly1305.svg](chacha20poly1305.svg)

Package chacha20poly1305 provides ChaCha20-Poly1305 AEAD (Authenticated
Encryption with Associated Data) for the I2P (Invisible Internet Project)
anonymous networking ecosystem.

This package implements the IETF ChaCha20-Poly1305 AEAD construction as defined
in RFC 8439, combining the ChaCha20 stream cipher with the Poly1305 MAC for
authenticated encryption. This is the modern encryption standard for I2P tunnel
and garlic message encryption.

# Key Features

    - Authenticated encryption preventing message tampering
    - High performance on modern CPUs (faster than AES on systems without AES-NI)
    - Constant-time implementation resistant to timing attacks
    - Support for additional authenticated data (AAD)

# Usage Example

    // Generate a random key
    key, _ := chacha20poly1305.GenerateKey()

    // Create AEAD cipher
    aead, _ := chacha20poly1305.NewAEAD(key)

    // Encrypt with associated data
    plaintext := []byte("Secret message")
    associatedData := []byte("public metadata")
    nonce := make([]byte, chacha20poly1305.NonceSize)
    rand.Read(nonce)

    ciphertext, tag, _ := aead.Encrypt(plaintext, associatedData, nonce)

    // Decrypt and verify
    decrypted, _ := aead.Decrypt(ciphertext, tag[:], associatedData, nonce)

# Security Considerations

    - Never reuse a nonce with the same key - this breaks authentication
    - Generate nonces using a cryptographically secure random number generator
    - Use unique keys for different encryption contexts
    - Verify the authentication tag before processing decrypted data

# ChaCha20-Poly1305 in I2P

I2P uses ChaCha20-Poly1305 for garlic message encryption
(ECIES-X25519-AEAD-Ratchet), tunnel layer encryption, and session-based
messaging with forward secrecy. Those code paths in this repository (the ecies,
tunnel, curve25519, and ratchet packages) call
golang.org/x/crypto/chacha20poly1305 directly. This package is a standalone
wrapper around the same RFC 8439 construction that provides a separate
Encrypt/Decrypt (ciphertext + detached tag) API; it is not currently wired into
those protocol paths.

## Usage

```go
const (
	// KeySize is the size of the ChaCha20-Poly1305 key in bytes (256 bits)
	KeySize = 32

	// NonceSize is the size of the nonce in bytes for ChaCha20-Poly1305
	// Standard IETF ChaCha20-Poly1305 uses 12-byte nonces
	NonceSize = 12

	// TagSize is the size of the Poly1305 authentication tag in bytes (128 bits)
	TagSize = 16
)
```

```go
var (
	// ErrInvalidKeySize indicates the key is not 32 bytes.
	// It is reserved and is not currently returned by this package: NewAEAD takes
	// a fixed [32]byte array, so an invalid key size cannot be expressed at the API.
	ErrInvalidKeySize = oops.Errorf("invalid ChaCha20-Poly1305 key size: must be 32 bytes")

	// ErrInvalidNonceSize indicates the nonce is not 12 bytes
	ErrInvalidNonceSize = oops.Errorf("invalid ChaCha20-Poly1305 nonce size: must be 12 bytes")

	// ErrAuthenticationFailed indicates Poly1305 tag verification failed
	ErrAuthenticationFailed = oops.Errorf("ChaCha20-Poly1305 authentication failed: message has been tampered with")

	// ErrInvalidCiphertext indicates the ciphertext format is invalid
	ErrInvalidCiphertext = oops.Errorf("invalid ciphertext: too short or malformed")
)
```
Common errors for ChaCha20-Poly1305 AEAD operations

#### func  GenerateKey

```go
func GenerateKey() ([KeySize]byte, error)
```
GenerateKey creates a new random 32-byte ChaCha20-Poly1305 key using a
cryptographically secure random number generator.

Returns:

    - [32]byte: A random key suitable for use with NewAEAD
    - error: Any error from the random number generator

Example:

    key, err := chacha20poly1305.GenerateKey()
    if err != nil {
        return err
    }
    aead, _ := chacha20poly1305.NewAEAD(key)

#### func  GenerateNonce

```go
func GenerateNonce() ([NonceSize]byte, error)
```
GenerateNonce creates a new random 12-byte nonce suitable for use with
ChaCha20-Poly1305. Each nonce must be unique for a given key - never reuse a
nonce with the same key.

Returns:

    - [12]byte: A random nonce
    - error: Any error from the random number generator

Example:

    nonce, err := chacha20poly1305.GenerateNonce()
    if err != nil {
        return err
    }
    ciphertext, tag, _ := aead.Encrypt(plaintext, aad, nonce[:])

#### type AEAD

```go
type AEAD struct {
}
```

AEAD provides ChaCha20-Poly1305 authenticated encryption with associated data.
This cipher combines the ChaCha20 stream cipher with the Poly1305 MAC to provide
both confidentiality and authenticity for encrypted messages.

The AEAD cipher is safe for concurrent use by multiple goroutines.

#### func  NewAEAD

```go
func NewAEAD(key [KeySize]byte) (*AEAD, error)
```
NewAEAD creates a new ChaCha20-Poly1305 AEAD cipher with the given key.

Parameters:

    - key: A 32-byte ChaCha20-Poly1305 key. The key length is enforced by the
      [KeySize]byte type, so it is always exactly 32 bytes.

Returns:

    - *AEAD: The initialized AEAD cipher
    - error: A wrapped error if the underlying cipher cannot be created

Example:

    key := [32]byte{...}  // Your 32-byte key
    aead, err := NewAEAD(key)
    if err != nil {
        log.Fatal(err)
    }

#### func (*AEAD) Decrypt

```go
func (a *AEAD) Decrypt(ciphertext, tag, associatedData, nonce []byte) (plaintext []byte, err error)
```
Decrypt decrypts ciphertext and verifies the authentication tag using
ChaCha20-Poly1305. If the tag verification fails, this method returns
ErrAuthenticationFailed and the ciphertext should be discarded as it may have
been tampered with.

Parameters:

    - ciphertext: The encrypted data
    - tag: The 16-byte Poly1305 authentication tag
    - associatedData: The same associated data used during encryption
    - nonce: The same 12-byte nonce used during encryption

Returns:

    - plaintext: The decrypted data (only valid if error is nil)
    - error: ErrAuthenticationFailed if verification fails, other errors for invalid inputs

Security: Always check the error before using the plaintext. If authentication
fails, the plaintext MUST be discarded as the message may have been tampered
with.

Example:

    plaintext, err := aead.Decrypt(ciphertext, tag, aad, nonce)
    if err != nil {
        // Authentication failed - ciphertext was tampered with
        return err
    }
    // Safe to use plaintext

#### func (*AEAD) Encrypt

```go
func (a *AEAD) Encrypt(plaintext, associatedData, nonce []byte) (ciphertext []byte, tag [TagSize]byte, err error)
```
Encrypt encrypts plaintext with associated data using ChaCha20-Poly1305 AEAD.
The associated data is authenticated but not encrypted - it's useful for
metadata that must be verified but doesn't need confidentiality.

Parameters:

    - plaintext: The data to encrypt
    - associatedData: Additional data to authenticate (can be nil)
    - nonce: A 12-byte nonce (must be unique for each encryption with the same key)

Returns:

    - ciphertext: The encrypted data (same length as plaintext)
    - tag: The 16-byte Poly1305 authentication tag
    - error: Any error during encryption (e.g., invalid nonce size)

Security: Never reuse a nonce with the same key. This breaks the authentication
guarantee and can leak information about the plaintext.

Example:

    plaintext := []byte("Secret message")
    aad := []byte("public header")
    nonce := make([]byte, chacha20poly1305.NonceSize)
    rand.Read(nonce)

    ciphertext, tag, err := aead.Encrypt(plaintext, aad, nonce)



chacha20poly1305 

github.com/go-i2p/crypto/chacha20poly1305

[go-i2p template file](/template.md)
