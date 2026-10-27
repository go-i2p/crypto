package ratchet

import (
	"github.com/go-i2p/crypto/hkdf"
	"github.com/go-i2p/crypto/kdf"
	"github.com/samber/oops"
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
func DH_INITIALIZEFull(rootKey [ChainKeySize]byte, k [32]byte) (nextRootKey, ck [32]byte, err error) {
	keydata, err := kdf.StandardHKDF(rootKey[:], k[:], []byte("KDFDHRatchetStep"), 64)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	copy(nextRootKey[:], keydata[0:32])
	copy(ck[:], keydata[32:64])
	return nextRootKey, ck, nil
}

// Split implements the Noise Split() function that the I2P ECIES spec requires
// after the final handshake KDF (section 4a, DH Ratchet):
//
//	"After the final handshake KDF on bound sessions, Bob and Alice must run
//	the Noise Split() function on the resulting CipherState to create
//	independent symmetric and tag chain keys for inbound and outbound
//	sessions."
//
// Noise (protocol.pdf section 5.2.3) defines Split on the SymmetricState
// chaining key:
//
//	temp_hk = HKDF(ck, zerolen, "", 64)
//	temp_k1 = temp_hk[0:32]
//	temp_k2 = temp_hk[32:64]
//
// The two outputs seed the two directions, so that inbound and outbound
// messages never share a key chain, a tag chain, or a nonce counter. The
// initiator uses temp_k1 to send and temp_k2 to receive; the responder uses
// them the other way round (see Role).
//
// The input chain key is treated as spent: Noise zeroes ck after Split, and
// callers must not derive anything else from it.
func Split(chainKey [ChainKeySize]byte) (k1, k2 [ChainKeySize]byte, err error) {
	keydata, err := kdf.StandardHKDF(chainKey[:], nil, nil, 64)
	if err != nil {
		return k1, k2, oops.Wrapf(ErrKeyDerivationFailed, "Noise Split failed: %w", err)
	}
	copy(k1[:], keydata[0:32])
	copy(k2[:], keydata[32:64])
	// Zero the expanded key material; the caller no longer needs ck.
	clear(keydata)
	return k1, k2, nil
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
