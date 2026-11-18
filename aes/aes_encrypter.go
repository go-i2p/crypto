package aes

import (
	"crypto/cipher"

	"github.com/go-i2p/logger"
)

// AESSymmetricEncrypter implements the Encrypter interface using AES
type AESSymmetricEncrypter struct {
	Key []byte
	IV  []byte
}

// Encrypt encrypts data using AES-CBC without padding. The data length must be
// a multiple of the 16-byte AES block size; callers are responsible for any
// padding. This matches how I2P uses AES-CBC (unpadded, over fixed-size payload
// regions).
func (e *AESSymmetricEncrypter) Encrypt(data []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "aes", "func": "AESSymmetricEncrypter.Encrypt", "data_length": len(data)}).Debug("Encrypting data")
	return processCBCNoPadding(e.Key, e.IV, data, cipher.NewCBCEncrypter)
}
