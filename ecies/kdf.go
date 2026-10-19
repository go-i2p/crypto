package ecies

import (
	"crypto/subtle"
	"time"

	"github.com/go-i2p/crypto/ratchet"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

// DeriveMessageKey derives the message encryption key at position
// messageNumber of the symmetric key ratchet chain that starts at chainKey.
//
// Per the I2P ECIES spec (section 4c), the chain key must be ratcheted
// messageNumber times before deriving:
//
//	keydata_n = HKDF(symmKey_chainKey_(n-1), SYMMKEY_CONSTANT, "SymmetricRatchet", 64)
//	k_n       = keydata_n[32:64]
//
// The message number is therefore *not* mixed into the KDF itself; it selects
// how far along the one-way chain the caller walks. Deriving without advancing
// would return k_0 for every n, handing different messages the same key.
//
// chainKey: The current chain key (32 bytes)
// messageNumber: The message sequence number for this key
// Returns (messageKey, error)
func DeriveMessageKey(chainKey []byte, messageNumber uint32) ([32]byte, error) {
	if len(chainKey) != 32 {
		return [32]byte{}, oops.Errorf("invalid chain key size: expected 32, got %d", len(chainKey))
	}

	var chainKeyArray [32]byte
	copy(chainKeyArray[:], chainKey)

	ratchetInstance := ratchet.NewSymmetricRatchet(chainKeyArray)

	// Walk the chain forward to the requested position.
	for i := uint32(0); i < messageNumber; i++ {
		if err := ratchetInstance.Advance(); err != nil {
			return [32]byte{}, err
		}
	}

	messageKey, err := ratchetInstance.DeriveMessageKey(messageNumber)
	if err != nil {
		return [32]byte{}, err
	}

	return messageKey, nil
}

// DeriveSessionTag derives the session tag at position tagNumber of a tag set.
//
// chainKey is the session tag chain key seed (sessTag_ck) — the value the DH
// ratchet outputs before the tag set is initialized. It is NOT an already
// advanced live chain key: this function runs the spec's STInitialization KDF
// on it (via [ratchet.NewTagRatchet]) to obtain the first chain key, then steps
// the ratchet to tagNumber. Passing a chain key that has already been through
// STInitialization would initialize the ratchet a second time and yield tags
// that do not match the session's.
//
// tagNumber: The tag sequence number (0 produces tag_0)
// Returns (tag, error) where tag is 8 bytes
func DeriveSessionTag(chainKey []byte, tagNumber uint32) ([8]byte, error) {
	if len(chainKey) != 32 {
		return [8]byte{}, oops.Errorf("invalid chain key size: expected 32, got %d", len(chainKey))
	}

	var chainKeyArray [32]byte
	copy(chainKeyArray[:], chainKey)

	ratchetInstance := ratchet.NewTagRatchet(chainKeyArray)

	// Advance to the desired tag number
	for i := uint32(0); i < tagNumber; i++ {
		if _, err := ratchetInstance.GenerateNextTag(); err != nil {
			return [8]byte{}, err
		}
	}

	// Generate the tag at the desired position
	tag, err := ratchetInstance.GenerateNextTag()
	if err != nil {
		return [8]byte{}, err
	}

	return tag, nil
}

// performDH performs X25519 Diffie-Hellman key agreement.
// privateKey: Our X25519 private key (32 bytes)
// publicKey: Their X25519 public key (32 bytes)
// Returns: Shared secret (32 bytes)
func performDH(privateKey, publicKey []byte) ([]byte, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, oops.Errorf("invalid private key size: expected %d, got %d", PrivateKeySize, len(privateKey))
	}
	if len(publicKey) != PublicKeySize {
		return nil, oops.Errorf("invalid public key size: expected %d, got %d", PublicKeySize, len(publicKey))
	}

	// Convert to X25519 key types
	privKey := x25519.PrivateKey(privateKey)
	pubKey := x25519.PublicKey(publicKey)

	// Perform X25519 DH
	sharedSecret, err := privKey.SharedKey(pubKey)
	if err != nil {
		return nil, oops.Errorf("X25519 key agreement failed: %w", err)
	}

	return sharedSecret, nil
}

// constantTimeEqual performs constant-time comparison of two byte slices.
// This prevents timing attacks when comparing secrets like session tags or MACs.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// currentTimestamp returns the current Unix timestamp in seconds.
// This is used for session creation timestamps.
func currentTimestamp() int64 {
	return time.Now().Unix()
}
