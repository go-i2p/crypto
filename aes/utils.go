package aes

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/samber/oops"
)

// processCBCNoPadding performs AES-CBC encryption or decryption without padding,
// using the provided block mode constructor for direction selection. The data
// length must be a multiple of the AES block size; callers are responsible for
// any padding. This matches how I2P uses AES-CBC (unpadded, over fixed-size
// payload regions) rather than the PKCS#7-style padding common in general-purpose
// crypto libraries.
func processCBCNoPadding(key, iv, data []byte, newBlockMode func(cipher.Block, []byte) cipher.BlockMode) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, oops.Errorf("data length must be a multiple of block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	output := make([]byte, len(data))
	mode := newBlockMode(block, iv)
	mode.CryptBlocks(output, data)
	return output, nil
}
