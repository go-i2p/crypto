package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
)

// Tunnel represents a cryptographic tunnel with layer and IV encryption keys.
// Moved from: tunnel.go
type Tunnel struct {
	layerKey cipher.Block
	ivKey    cipher.Block
}

// NewTunnelCrypto creates a new tunnel cryptographic instance with the provided keys.
// Returns a new Tunnel instance or an error if cipher creation fails.
// Moved from: tunnel.go
func NewTunnelCrypto(layerKey, ivKey TunnelKey) (t *Tunnel, err error) {
	log.Debug("Creating new Tunnel crypto")
	t = new(Tunnel)
	t.layerKey, err = aes.NewCipher(layerKey[:])
	if err == nil {
		t.ivKey, err = aes.NewCipher(ivKey[:])
	}

	if err != nil {
		// error happened we don't need t
		// log.WithError(err).Error("Failed to create Tunnel crypto")
		t = nil
	} else {
		log.Debug("Tunnel crypto created successfully")
	}
	return
}

// Encrypt encrypts tunnel data in place using the tunnel's encryption keys.
// Moved from: tunnel.go
func (t *Tunnel) Encrypt(td *TunnelData) {
	log.Debug("Encrypting Tunnel data")
	data := *td
	t.ivKey.Encrypt(data[16:1024], data[16:1024])
	layerBlock := cipher.NewCBCEncrypter(t.layerKey, data[:16])
	layerBlock.CryptBlocks(data[16:1024], data[16:1024])
	t.ivKey.Encrypt(data[16:1024], data[16:1024])
	log.Debug("Tunnel data encrypted successfully")
}

// Decrypt decrypts tunnel data in place using the tunnel's decryption keys.
// Moved from: tunnel.go
func (t *Tunnel) Decrypt(td *TunnelData) {
	log.Debug("Decrypting Tunnel data")
	data := *td
	t.ivKey.Decrypt(data[16:1024], data[16:1024])
	layerBlock := cipher.NewCBCDecrypter(t.layerKey, data[:16])
	layerBlock.CryptBlocks(data[16:1024], data[16:1024])
	t.ivKey.Decrypt(data[16:1024], data[16:1024])
	log.Debug("Tunnel data decrypted successfully")
}
