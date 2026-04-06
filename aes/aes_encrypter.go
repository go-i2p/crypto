package aes

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/go-i2p/logger"
)

// AESSymmetricEncrypter implements the Encrypter interface using AES
type AESSymmetricEncrypter struct {
	Key []byte
	IV  []byte
}

// Encrypt encrypts data using AES-CBC with PKCS#7 padding
func (e *AESSymmetricEncrypter) Encrypt(data []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "aes", "func": "AESSymmetricEncrypter.Encrypt", "data_length": len(data)}).Debug("Encrypting data")

	block, err := aes.NewCipher(e.Key)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "aes", "func": "AESSymmetricEncrypter.Encrypt"}).WithError(err).Error("Failed to create AES cipher")
		return nil, err
	}

	plaintext := pkcs7Pad(data, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, e.IV)
	mode.CryptBlocks(ciphertext, plaintext)

	log.WithFields(logger.Fields{"pkg": "aes", "func": "AESSymmetricEncrypter.Encrypt", "ciphertext_length": len(ciphertext)}).Debug("Data encrypted successfully")
	return ciphertext, nil
}

// EncryptNoPadding encrypts data using AES-CBC without padding
func (e *AESSymmetricEncrypter) EncryptNoPadding(data []byte) ([]byte, error) {
	return processCBCNoPadding(e.Key, e.IV, data, cipher.NewCBCEncrypter)
}
