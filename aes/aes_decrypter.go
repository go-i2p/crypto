package aes

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// AESSymmetricDecrypter implements the Decrypter interface using AES
type AESSymmetricDecrypter struct {
	Key []byte
	IV  []byte
}

// Decrypt decrypts data using AES-CBC with PKCS#7 padding
func (d *AESSymmetricDecrypter) Decrypt(data []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "aes", "func": "AESSymmetricDecrypter.Decrypt", "data_length": len(data)}).Debug("Decrypting data")

	block, err := aes.NewCipher(d.Key)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "aes", "func": "AESSymmetricDecrypter.Decrypt"}).WithError(err).Error("Failed to create AES cipher")
		return nil, err
	}

	if len(data)%aes.BlockSize != 0 {
		log.WithFields(logger.Fields{"pkg": "aes", "func": "AESSymmetricDecrypter.Decrypt"}).Error("Ciphertext is not a multiple of the block size")
		return nil, oops.Errorf("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, d.IV)
	mode.CryptBlocks(plaintext, data)

	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "aes", "func": "AESSymmetricDecrypter.Decrypt"}).WithError(err).Error("Failed to unpad plaintext")
		return nil, err
	}

	log.WithFields(logger.Fields{"pkg": "aes", "func": "AESSymmetricDecrypter.Decrypt", "plaintext_length": len(plaintext)}).Debug("Data decrypted successfully")
	return plaintext, nil
}

// DecryptNoPadding decrypts data using AES-CBC without padding
func (d *AESSymmetricDecrypter) DecryptNoPadding(data []byte) ([]byte, error) {
	return processCBCNoPadding(d.Key, d.IV, data, cipher.NewCBCDecrypter)
}

func NewCipher(c []byte) (cipher.Block, error) {
	return aes.NewCipher(c)
}
