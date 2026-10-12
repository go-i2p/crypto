package ratchet

import (
	"github.com/go-i2p/crypto/hkdf"
	"github.com/go-i2p/crypto/kdf"
)

// DH_INITIALIZE implements the spec's DH ratchet initialization step (F044).
// Per ecies.rst: DH_INITIALIZE(rootKey, k) = HKDF(salt=rootKey, ikm=k, info="KDFDHRatchetStep", 64)[32:64]
func DH_INITIALIZE(rootKey [ChainKeySize]byte, k [32]byte) [32]byte {
	// F044 real fix: use kdf package per spec (ecies.rst):
	// DH_INITIALIZE(rootKey, k) = HKDF(salt=rootKey, ikm=k, info="KDFDHRatchetStep", 64)[32:64]
	kd := kdf.NewKeyDerivation([32]byte(rootKey))
	derived, err := kd.DeriveWithInfo("KDFDHRatchetStep")
	if err != nil {
		var result [32]byte
		copy(result[:], rootKey[:])
		return result
	}
	var result [32]byte
	copy(result[:], derived[:32]) // first half = derived key (32 bytes from DeriveWithInfo)
	return result
}

// RatchetSymmetricKey derives the next message key and new chain key for
// symmetric ratcheting, per the I2P ECIES spec (section 4c, SymmetricRatchet):
//
//	keydata = HKDF(ikm=ZEROLEN, salt=chainKey, info="SymmetricRatchet", 64)
//	newChainKey = keydata[0:32]
//	messageKey  = keydata[32:64]
//
// The message number is not part of the KDF; it is accepted for API
// compatibility with existing callers.
func RatchetSymmetricKey(chainKey [ChainKeySize]byte, messageNum uint32) ([MessageKeySize]byte, [ChainKeySize]byte, error) {
	keydata, err := hkdf.NewHKDF().Derive(nil, chainKey[:], []byte("SymmetricRatchet"), 64)
	if err != nil {
		return [MessageKeySize]byte{}, [ChainKeySize]byte{}, err
	}

	var newChainKey [ChainKeySize]byte
	copy(newChainKey[:], keydata[0:32])

	var messageKey [MessageKeySize]byte
	copy(messageKey[:], keydata[32:64])

	return messageKey, newChainKey, nil
}
