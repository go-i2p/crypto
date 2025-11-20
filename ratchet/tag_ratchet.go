// Package ratchet session tag ratchet implementation.
package ratchet

import (
	"encoding/binary"

	"github.com/go-i2p/crypto/hmac"
)

// TagRatchet implements the session tag ratchet for deriving unique session tags.
// Session tags are 8-byte identifiers used to route existing session messages
// without revealing session metadata in cleartext.
//
// The ratchet uses HMAC-SHA256 to derive tags and chain keys, ensuring
// forward secrecy - past tags cannot be derived from current state.
type TagRatchet struct {
	chainKey [ChainKeySize]byte
	tagCount uint32
}

// NewTagRatchet creates a new session tag ratchet from an initial chain key.
func NewTagRatchet(initialChainKey [ChainKeySize]byte) *TagRatchet {
	return &TagRatchet{
		chainKey: initialChainKey,
		tagCount: 0,
	}
}

// GenerateNextTag derives the next 8-byte session tag and advances the ratchet.
// Each tag is uniquely derived from the chain key and tag count using HMAC-SHA256.
func (r *TagRatchet) GenerateNextTag() ([SessionTagSize]byte, error) {
	tag, err := r.deriveTag(r.tagCount)
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
	return r.deriveTag(r.tagCount)
}

// deriveTag derives an 8-byte tag from the chain key and tag number.
// Uses HMAC-SHA256(chainKey, "SessionTag" || tagNum) truncated to 8 bytes.
func (r *TagRatchet) deriveTag(tagNum uint32) ([SessionTagSize]byte, error) {
	// Prepare input: "SessionTag" || tagNum
	input := make([]byte, len("SessionTag")+4)
	copy(input, []byte("SessionTag"))
	binary.BigEndian.PutUint32(input[len("SessionTag"):], tagNum)

	// Compute HMAC using our existing hmac package
	var hmacKey hmac.HMACKey
	copy(hmacKey[:], r.chainKey[:])
	digest := hmac.I2PHMAC(input, hmacKey)

	// Truncate to 8 bytes for session tag
	var tag [SessionTagSize]byte
	copy(tag[:], digest[:SessionTagSize])

	return tag, nil
}

// Advance advances the tag ratchet by deriving a new chain key.
// Uses HMAC-SHA256(chainKey, "NextChainKey" || tagCount) for forward secrecy.
func (r *TagRatchet) Advance() error {
	// Prepare input: "NextChainKey" || tagCount
	input := make([]byte, len("NextChainKey")+4)
	copy(input, []byte("NextChainKey"))
	binary.BigEndian.PutUint32(input[len("NextChainKey"):], r.tagCount)

	// Compute HMAC using our existing hmac package
	var hmacKey hmac.HMACKey
	copy(hmacKey[:], r.chainKey[:])
	digest := hmac.I2PHMAC(input, hmacKey)

	// Update chain key (use full 32 bytes)
	copy(r.chainKey[:], digest[:ChainKeySize])

	// Increment tag count
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
	r.tagCount = 0
}
