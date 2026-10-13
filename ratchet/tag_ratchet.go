package ratchet

import (
	"github.com/go-i2p/crypto/kdf"
)

// TagRatchet implements the I2P ECIES session tag ratchet (spec section 4b).
// Session tags are 8-byte identifiers used to route existing session messages
// without revealing session metadata in cleartext.
//
// The ratchet is initialized from a session tag chain key (sessTag_ck) via the
// STInitialization KDF, which produces the first chain key and a per-tag-set
// constant (SESSTAG_CONSTANT). Each subsequent tag is derived by KDF_ST, which
// advances the chain key and emits an 8-byte session tag.
//
// Per ecies.rst (Session Tag Ratchet KDF):
//
//	// Initialization
//	keydata = HKDF(sessTag_ck, ZEROLEN, "STInitialization", 64)
//	sessTag_chainKey = keydata[0:32]
//	SESSTAG_CONSTANT = keydata[32:64]
//
//	// KDF_ST(ck, constant)
//	keydata = HKDF(sessTag_chainKey, SESSTAG_CONSTANT, "SessionTagKeyGen", 64)
//	sessTag_chainKey = keydata[0:32]
//	tag = keydata[32:40]
//
// ⚠️ CRITICAL SECURITY WARNING:
// Do NOT construct TagRatchet directly using var or struct literals.
// Always use NewTagRatchet() to ensure proper initialization.
//
// BAD:
//
//	var ratchet TagRatchet             // Zero chain key - cryptographically invalid!
//	ratchet := TagRatchet{...}         // Missing validation
//
// GOOD:
//
//	ratchet := NewTagRatchet(sessTagCK)
type TagRatchet struct {
	chainKey     [ChainKeySize]byte
	sesstagConst [ChainKeySize]byte
	tagCount     uint32
}

// NewTagRatchet creates a new session tag ratchet from a session tag chain key
// (sessTag_ck), running the STInitialization KDF to derive the first chain key
// and the per-tag-set SESSTAG_CONSTANT.
func NewTagRatchet(sessTagCK [ChainKeySize]byte) *TagRatchet {
	r := &TagRatchet{}
	keydata, err := kdf.StandardHKDF(sessTagCK[:], nil, []byte("STInitialization"), 64)
	if err != nil {
		// HKDF over a 32-byte salt cannot fail; leave the ratchet zeroed.
		return r
	}
	copy(r.chainKey[:], keydata[0:32])
	copy(r.sesstagConst[:], keydata[32:64])
	return r
}

// GenerateNextTag derives the next 8-byte session tag and advances the ratchet.
func (r *TagRatchet) GenerateNextTag() ([SessionTagSize]byte, error) {
	tag, err := r.deriveTag()
	if err != nil {
		return [SessionTagSize]byte{}, err
	}

	// Advance the ratchet
	if err := r.Advance(); err != nil {
		return [SessionTagSize]byte{}, err
	}

	return tag, nil
}

// PeekNextTag derives the next session tag without advancing the ratchet.
// This is used for tag validation without commitment.
func (r *TagRatchet) PeekNextTag() ([SessionTagSize]byte, error) {
	return r.deriveTag()
}

// deriveTag computes the next session tag from the current chain key via
// KDF_ST, without mutating the stored chain key.
func (r *TagRatchet) deriveTag() ([SessionTagSize]byte, error) {
	keydata, err := kdf.StandardHKDF(r.chainKey[:], r.sesstagConst[:], []byte("SessionTagKeyGen"), 64)
	if err != nil {
		return [SessionTagSize]byte{}, err
	}
	var tag [SessionTagSize]byte
	copy(tag[:], keydata[32:40])
	return tag, nil
}

// Advance advances the tag ratchet by deriving a new chain key via KDF_ST.
func (r *TagRatchet) Advance() error {
	keydata, err := kdf.StandardHKDF(r.chainKey[:], r.sesstagConst[:], []byte("SessionTagKeyGen"), 64)
	if err != nil {
		return err
	}
	copy(r.chainKey[:], keydata[0:32])
	r.tagCount++
	return nil
}

// GetTagCount returns the current tag count (number of tags generated).
func (r *TagRatchet) GetTagCount() uint32 {
	return r.tagCount
}

// Zero securely clears the tag ratchet state from memory.
func (r *TagRatchet) Zero() {
	for i := range r.chainKey {
		r.chainKey[i] = 0
	}
	for i := range r.sesstagConst {
		r.sesstagConst[i] = 0
	}
	r.tagCount = 0
}
