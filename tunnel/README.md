# tunnel
--
    import "github.com/go-i2p/crypto/tunnel"

![tunnel.svg](tunnel.svg)

package for i2p specific crpytography

## Usage

#### type Tunnel

```go
type Tunnel struct {
}
```

Tunnel represents a cryptographic tunnel with layer and IV encryption keys.
Moved from: tunnel.go

#### func  NewTunnelCrypto

```go
func NewTunnelCrypto(layerKey, ivKey TunnelKey) (t *Tunnel, err error)
```
NewTunnelCrypto creates a new tunnel cryptographic instance with the provided
keys. Returns a new Tunnel instance or an error if cipher creation fails. Moved
from: tunnel.go

#### func (*Tunnel) Decrypt

```go
func (t *Tunnel) Decrypt(td *TunnelData)
```
Decrypt decrypts tunnel data in place using the tunnel's decryption keys. Moved
from: tunnel.go

#### func (*Tunnel) Encrypt

```go
func (t *Tunnel) Encrypt(td *TunnelData)
```
Encrypt encrypts tunnel data in place using the tunnel's encryption keys. Moved
from: tunnel.go

#### type TunnelData

```go
type TunnelData [1028]byte
```

TunnelData represents the data structure for tunnel messages (1028 bytes). Moved
from: tunnel.go

#### type TunnelIV

```go
type TunnelIV []byte
```

TunnelIV represents the initialization vector for a tunnel message. Moved from:
tunnel.go

#### type TunnelKey

```go
type TunnelKey [32]byte
```

TunnelKey represents a symmetric key for encrypting tunnel messages (32 bytes).
Moved from: tunnel.go



tunnel 

github.com/go-i2p/crypto/tunnel

[go-i2p template file](/template.md)
