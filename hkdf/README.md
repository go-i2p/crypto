# hkdf
--
    import "github.com/go-i2p/crypto/hkdf"

![hkdf.svg](hkdf.svg)



## Usage

```go
const (
	DefaultKeyLength = 32  // 256 bits for ChaCha20
	MaxInfoLength    = 255 // Maximum info length for HKDF
)
```
Default parameters for I2P compatibility

```go
var (
	ErrInvalidKeyLength    = oops.Errorf("invalid key length")
	ErrInvalidSaltLength   = oops.Errorf("invalid salt length")
	ErrInvalidInfoLength   = oops.Errorf("invalid info length")
	ErrKeyDerivationFailed = oops.Errorf("key derivation failed")
)
```
Common HKDF errors

#### type HKDF

```go
type HKDF interface {
	// Derive derives a key of the specified length from the input key material (IKM)
	// salt: optional salt value (can be nil)
	// info: optional context and application-specific information (can be nil)
	// keyLen: desired length of the derived key in bytes
	Derive(ikm, salt, info []byte, keyLen int) ([]byte, error)

	// DeriveDefault derives a key using default parameters (32 bytes, no salt, no info)
	DeriveDefault(ikm []byte) ([]byte, error)
}
```

HKDF interface for key derivation function

#### func  NewHKDF

```go
func NewHKDF() HKDF
```
NewHKDF creates a new HKDF instance with SHA-256

#### func  NewHKDFWithHash

```go
func NewHKDFWithHash(hashFunc func() hash.Hash) HKDF
```
NewHKDFWithHash creates a new HKDF instance with custom hash function

#### type HKDFImpl

```go
type HKDFImpl struct {
}
```

HKDFImpl is the concrete implementation of HKDF using SHA-256

#### func (*HKDFImpl) Derive

```go
func (h *HKDFImpl) Derive(ikm, salt, info []byte, keyLen int) ([]byte, error)
```
Derive derives a key of the specified length from the input key material (IKM)

#### func (*HKDFImpl) DeriveDefault

```go
func (h *HKDFImpl) DeriveDefault(ikm []byte) ([]byte, error)
```
DeriveDefault derives a key using default parameters (32 bytes, no salt, no
info)



hkdf 

github.com/go-i2p/crypto/hkdf

[go-i2p template file](/template.md)
