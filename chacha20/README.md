# chacha20
--
    import "github.com/go-i2p/crypto/chacha20"

![chacha20.svg](chacha20.svg)



## Usage

```go
const (
	KeySize   = 32
	NonceSize = 12 // ChaCha20-Poly1305 standard nonce size
	TagSize   = 16 // Poly1305 authentication tag size
)
```
Key and nonce size constants for ChaCha20 Moved from: chacha20.go

```go
var (
	ErrInvalidKeySize   = oops.Errorf("invalid ChaCha20 key size")
	ErrInvalidNonceSize = oops.Errorf("invalid ChaCha20 nonce size")
	ErrEncryptFailed    = oops.Errorf("ChaCha20 encryption failed")
	ErrDecryptFailed    = oops.Errorf("ChaCha20 decryption failed")
	ErrAuthFailed       = oops.Errorf("ChaCha20-Poly1305 authentication failed")
)
```
Error constants for ChaCha20 operations Moved from: chacha20.go

#### type ChaCha20Key

```go
type ChaCha20Key [KeySize]byte
```

ChaCha20Key represents a 256-bit key for ChaCha20 encryption/decryption
operations. Moved from: chacha20.go

#### func  GenerateKey

```go
func GenerateKey() (*ChaCha20Key, error)
```
GenerateKey creates a new random ChaCha20 key

#### func (*ChaCha20Key) Bytes

```go
func (k *ChaCha20Key) Bytes() []byte
```
Bytes returns the key as a byte slice

#### func (*ChaCha20Key) Len

```go
func (k *ChaCha20Key) Len() int
```
Len returns the length of the key in bytes

#### func (*ChaCha20Key) NewDecrypter

```go
func (k *ChaCha20Key) NewDecrypter() (types.Decrypter, error)
```
NewDecrypter creates a new decrypter using this key

#### func (*ChaCha20Key) NewEncrypter

```go
func (k *ChaCha20Key) NewEncrypter() (types.Encrypter, error)
```
NewEncrypter creates a new encrypter using this key

#### type ChaCha20Nonce

```go
type ChaCha20Nonce [NonceSize]byte
```

ChaCha20Nonce represents a 96-bit nonce for ChaCha20-Poly1305 AEAD operations.
Moved from: chacha20.go

#### func  NewRandomNonce

```go
func NewRandomNonce() (ChaCha20Nonce, error)
```
NewRandomNonce generates a cryptographically secure random nonce for ChaCha20.
Returns a 96-bit nonce suitable for ChaCha20-Poly1305 AEAD encryption. Moved
from: chacha20.go

#### type ChaCha20PolyDecrypter

```go
type ChaCha20PolyDecrypter struct {
	Key ChaCha20Key
}
```

ChaCha20PolyDecrypter implements the Decrypter interface using ChaCha20-Poly1305

#### func (*ChaCha20PolyDecrypter) Decrypt

```go
func (d *ChaCha20PolyDecrypter) Decrypt(data []byte) ([]byte, error)
```
Decrypt decrypts data encrypted with ChaCha20-Poly1305 The format should be:
[12-byte nonce][ciphertext+tag]

#### func (*ChaCha20PolyDecrypter) DecryptWithAd

```go
func (d *ChaCha20PolyDecrypter) DecryptWithAd(data, ad []byte) ([]byte, error)
```
DecryptWithAd decrypts data encrypted with ChaCha20-Poly1305 using additional
data

#### type ChaCha20PolyEncrypter

```go
type ChaCha20PolyEncrypter struct {
	Key ChaCha20Key
}
```

ChaCha20PolyEncrypter implements the Encrypter interface using ChaCha20-Poly1305

#### func (*ChaCha20PolyEncrypter) Encrypt

```go
func (e *ChaCha20PolyEncrypter) Encrypt(data []byte) ([]byte, error)
```
Encrypt encrypts data using ChaCha20-Poly1305 with a random nonce The format is:
[12-byte nonce][ciphertext+tag]

#### func (*ChaCha20PolyEncrypter) EncryptWithAd

```go
func (e *ChaCha20PolyEncrypter) EncryptWithAd(data, ad []byte) ([]byte, error)
```
EncryptWithAd encrypts data using ChaCha20-Poly1305 with a random nonce and
additional authenticated data



chacha20 

github.com/go-i2p/crypto/chacha20

[go-i2p template file](/template.md)
