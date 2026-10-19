package ratchet

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Logger instance for ratchet package operations
var log = logger.GetGoI2PLogger()

// Constants for ratchet operations
const (
	// ChainKeySize is the size of chain keys in bytes
	ChainKeySize = 32
	// SessionTagSize is the size of session tags in bytes
	SessionTagSize = 8
	// MessageKeySize is the size of message keys in bytes
	MessageKeySize = 32
	// PublicKeySize is the size of X25519 public keys in bytes
	PublicKeySize = 32
	// PrivateKeySize is the size of X25519 private keys in bytes
	PrivateKeySize = 32
	// NonceSize is the size of the ChaCha20-Poly1305 AEAD nonce in bytes. Per
	// the I2P ECIES spec section 3 the first four bytes are always zero and the
	// last eight are the little-endian message number.
	NonceSize = 12

	// MaxMessagesPerTagset is the maximum valid AEAD message number for a
	// single tag set, inclusive. Per the I2P ECIES spec (section 3): "Maximum
	// value is 65535. Higher values must never be used." Because 65535 is a
	// valid number, a tag set carries numbers 0..65535, i.e. up to 65536
	// messages, matching the spec's "A Tag Set can be up to 65536 tags."
	// The DH ratchet must advance only once the counter exceeds this value.
	MaxMessagesPerTagset = 65535

	// DefaultLookaheadWindow is the default receiver look-ahead window size
	// for session tag validation. Per the I2P ECIES spec (section 4b):
	// "N might be at most 128, but 32 or even less may be a better choice."
	DefaultLookaheadWindow = 32

	// MaxLookaheadWindow is the maximum receiver look-ahead window size
	// permitted by the I2P ECIES spec (section 4b).
	MaxLookaheadWindow = 128
)

// Error constants for ratchet operations
var (
	ErrInvalidChainKeySize   = oops.Errorf("invalid chain key size")
	ErrInvalidPublicKeySize  = oops.Errorf("invalid public key size")
	ErrInvalidPrivateKeySize = oops.Errorf("invalid private key size")
	ErrTagDerivationFailed   = oops.Errorf("session tag derivation failed")
	ErrKeyDerivationFailed   = oops.Errorf("key derivation failed")
	ErrDHFailed              = oops.Errorf("Diffie-Hellman exchange failed")

	// ErrTagsetExhausted indicates the current tag set has used every valid
	// message number (0..MaxMessagesPerTagset inclusive) and the DH ratchet
	// must advance before further messages can be sent.
	ErrTagsetExhausted = oops.Errorf("tag set exhausted: DH ratchet required")
)
