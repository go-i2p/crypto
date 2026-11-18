package aes

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/go-i2p/logger"
)

// AESSymmetricDecrypter implements the Decrypter interface using AES
type AESSymmetricDecrypter struct {
	Key []byte
	IV  []byte
}

// Decrypt decrypts data using AES-CBC without padding. The ciphertext length
// must be a multiple of the 16-byte AES block size. This matches how I2P uses
// AES-CBC (unpadded, over fixed-size payload regions).
func (d *AESSymmetricDecrypter) Decrypt(data []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "aes", "func": "AESSymmetricDecrypter.Decrypt", "data_length": len(data)}).Debug("Decrypting data")
	return processCBCNoPadding(d.Key, d.IV, data, cipher.NewCBCDecrypter)
}

func NewCipher(c []byte) (cipher.Block, error) {
	return aes.NewCipher(c)
}
