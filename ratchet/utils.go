// Package ratchet utility functions.
package ratchet

import (
	"encoding/binary"

	"github.com/go-i2p/crypto/hmac"
)

// RatchetSymmetricKey is a helper function that derives the next message key
// and new chain key for symmetric ratcheting.
// This combines message key derivation and chain key advancement in one operation.
func RatchetSymmetricKey(chainKey [ChainKeySize]byte, messageNum uint32) ([MessageKeySize]byte, [ChainKeySize]byte, error) {
	// Derive message key: HMAC-SHA256(chainKey, "MessageKey" || messageNum)
	msgInput := make([]byte, len("MessageKey")+4)
	copy(msgInput, []byte("MessageKey"))
	binary.BigEndian.PutUint32(msgInput[len("MessageKey"):], messageNum)

	var msgHmacKey hmac.HMACKey
	copy(msgHmacKey[:], chainKey[:])
	msgDigest := hmac.I2PHMAC(msgInput, msgHmacKey)

	var messageKey [MessageKeySize]byte
	copy(messageKey[:], msgDigest[:MessageKeySize])

	// Derive next chain key: HMAC-SHA256(chainKey, "NextChainKey" || messageNum)
	chainInput := make([]byte, len("NextChainKey")+4)
	copy(chainInput, []byte("NextChainKey"))
	binary.BigEndian.PutUint32(chainInput[len("NextChainKey"):], messageNum)

	var chainHmacKey hmac.HMACKey
	copy(chainHmacKey[:], chainKey[:])
	chainDigest := hmac.I2PHMAC(chainInput, chainHmacKey)

	var newChainKey [ChainKeySize]byte
	copy(newChainKey[:], chainDigest[:ChainKeySize])

	return messageKey, newChainKey, nil
}
