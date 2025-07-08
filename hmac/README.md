# hmac
--
    import "github.com/go-i2p/crypto/hmac"

![hmac.svg](hmac.svg)



## Usage

#### type HMACDigest

```go
type HMACDigest [32]byte
```

HMACDigest represents a 256-bit HMAC-SHA256 digest output. Moved from: hmac.go

#### func  I2PHMAC

```go
func I2PHMAC(data []byte, k HMACKey) (d HMACDigest)
```
I2PHMAC computes HMAC-SHA256 using the provided key and data. This function
implements the I2P standard HMAC computation using SHA256. Moved from: hmac.go

#### type HMACKey

```go
type HMACKey [32]byte
```

HMACKey represents a 256-bit key for HMAC-SHA256 operations. Moved from: hmac.go



hmac 

github.com/go-i2p/crypto/hmac

[go-i2p template file](/template.md)
