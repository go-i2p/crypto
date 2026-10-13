package ratchet

import (
	"github.com/go-i2p/crypto/hkdf"
	"github.com/go-i2p/crypto/kdf"
)

// DH_INITIALIZE implements the spec's DH ratchet initialization step.
// Per ecies.rst (DH INITIALIZATION KDF):
//
//	keydata = HKDF(salt=rootKey, ikm=k, info="KDFDHRatchetStep", 64)
//	nextRootKey = keydata[0:32]
//	ck          = keydata[32:64]
//
// It returns the chain key (ck) that initializes the new session tag and
// symmetric key ratchets for the tag set. The nextRootKey (keydata[0:32]) is
// the KDF input for a subsequent DH ratchet in the same direction; callers
// that need it should use DH_INITIALIZEFull.
func DH_INITIALIZE(rootKey [ChainKeySize]byte, k [32]byte) [32]byte {
	_, ck, err := DH_INITIALIZEFull(rootKey, k)
	if err != nil {
		// HKDF over a 32-byte salt/ikm cannot fail; fall back to a zeroed
		// chain key rather than leaking the root key.
		return [32]byte{}
	}
	return ck
}

// DH_INITIALIZEFull implements the full spec DH INITIALIZATION KDF, returning
// both the next root key (keydata[0:32]) and the chain key (keydata[32:64]).
//
//	keydata = HKDF(salt=rootKey, ikm=k, info="KDFDHRatchetStep", 64)
func DH_INITIALIZEFull(rootKey [ChainKeySize]byte, k [32]byte) (nextRootKey [32]byte, ck [32]byte, err error) {
	keydata, err := kdf.StandardHKDF(rootKey[:], k[:], []byte("KDFDHRatchetStep"), 64)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	copy(nextRootKey[:], keydata[0:32])
	copy(ck[:], keydata[32:64])
	return nextRootKey, ck, nil
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
