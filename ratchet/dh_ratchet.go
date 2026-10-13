package ratchet

import (
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/logger"

	"github.com/samber/oops"
)

// DHRatchet implements the Diffie-Hellman ratchet for forward secrecy.
// It performs periodic DH key exchanges to derive new chain keys.
//
// The DH ratchet provides the strongest form of forward secrecy - even if
// an attacker compromises the current state, they cannot decrypt past messages.
//
// ⚠️ CRITICAL SECURITY WARNING:
// Do NOT construct DHRatchet directly using var or struct literals.
// Always use NewDHRatchet() to ensure proper initialization.
//
// BAD:
//
//	var ratchet DHRatchet              // Zero keys - cryptographically invalid!
//	ratchet := DHRatchet{...}          // Missing validation
//
// GOOD:
//
//	ratchet := NewDHRatchet(rootKey, ourPrivKey, theirPubKey)
type DHRatchet struct {
	ourPrivKey  [PrivateKeySize]byte // Our current ephemeral private key
	theirPubKey [PublicKeySize]byte  // Their current ephemeral public key
	rootKey     [ChainKeySize]byte   // Root key for KDF chain
}

// NewDHRatchet creates a new DH ratchet with initial root key and keys.
func NewDHRatchet(rootKey, ourPrivKey, theirPubKey [ChainKeySize]byte) *DHRatchet {
	return &DHRatchet{
		ourPrivKey:  ourPrivKey,
		theirPubKey: theirPubKey,
		rootKey:     rootKey,
	}
}

// PerformRatchet performs a DH ratchet step.
//
// Spec ref: ecies.rst §"DH Ratchet KDF" —
//
//	sharedSecret = DH(rask, rbpk)
//	tagsetKey = HKDF(sharedSecret, ZEROLEN, "XDHRatchetTagSet", 32)
//	rootKey = nextRootKey // from previous tagset in this direction
//	newTagSet = DH_INITIALIZE(rootKey, tagsetKey)
//
// Returns (nextRootKey, ck) where nextRootKey is the updated root key for
// the next ratchet step in this direction, and ck is the chain key output
// of DH_INITIALIZE. The caller must apply the TagAndKeyGenKeys KDF to ck
// to obtain the session tag chain key and symmetric key chain key.
func (r *DHRatchet) PerformRatchet() ([ChainKeySize]byte, [ChainKeySize]byte, error) {
	// Perform X25519 DH
	sharedSecret, err := r.performDH(r.ourPrivKey[:], r.theirPubKey[:])
	if err != nil {
		return [ChainKeySize]byte{}, [ChainKeySize]byte{}, oops.Wrapf(ErrDHFailed, "DH ratchet failed: %w", err)
	}

	// tagsetKey = HKDF(sharedSecret, ZEROLEN, "XDHRatchetTagSet", 32)
	tagsetKeyBytes, err := kdf.StandardHKDF(sharedSecret, nil, []byte("XDHRatchetTagSet"), 32)
	if err != nil {
		return [ChainKeySize]byte{}, [ChainKeySize]byte{}, oops.Wrapf(ErrKeyDerivationFailed, "DH ratchet tagset KDF failed: %w", err)
	}
	var tagsetKey [ChainKeySize]byte
	copy(tagsetKey[:], tagsetKeyBytes)

	// newTagSet = DH_INITIALIZE(rootKey, tagsetKey)
	// Reuses the previous rootKey (nextRootKey from the prior tagset).
	nextRootKey, ck, err := DH_INITIALIZEFull(r.rootKey, tagsetKey)
	if err != nil {
		return [ChainKeySize]byte{}, [ChainKeySize]byte{}, oops.Wrapf(ErrKeyDerivationFailed, "DH ratchet KDF failed: %w", err)
	}

	// Update root key to nextRootKey for the next ratchet step.
	r.rootKey = nextRootKey

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "DHRatchet.PerformRatchet"}).Debug("DH ratchet performed successfully")
	return nextRootKey, ck, nil
}

// SetRootKey sets the root key used as input to DH_INITIALIZE on the next
// PerformRatchet call. This is used by the Session to select the correct
// per-direction root key before performing a ratchet step.
func (r *DHRatchet) SetRootKey(rootKey [ChainKeySize]byte) {
	r.rootKey = rootKey
}

// UpdateKeys updates the DH ratchet with a new remote public key.
func (r *DHRatchet) UpdateKeys(newTheirPubKey []byte) error {
	if len(newTheirPubKey) != PublicKeySize {
		return oops.Wrapf(ErrInvalidPublicKeySize, "expected %d, got %d", PublicKeySize, len(newTheirPubKey))
	}

	copy(r.theirPubKey[:], newTheirPubKey)
	return nil
}

// GenerateNewKeyPair generates a new ephemeral key pair for this ratchet.
func (r *DHRatchet) GenerateNewKeyPair() ([PublicKeySize]byte, error) {
	pubKey, privKey, err := curve25519.GenerateX25519KeyPair()
	if err != nil {
		return [PublicKeySize]byte{}, oops.Wrapf(ErrKeyDerivationFailed, "failed to generate key pair: %w", err)
	}

	copy(r.ourPrivKey[:], privKey.Bytes())

	var pubKeyArray [PublicKeySize]byte
	copy(pubKeyArray[:], pubKey.Bytes())
	return pubKeyArray, nil
}

// GetPublicKey returns our current DH public key.
func (r *DHRatchet) GetPublicKey() ([PublicKeySize]byte, error) {
	// Derive public key from our private key
	privKey, err := curve25519.NewCurve25519PrivateKey(r.ourPrivKey[:])
	if err != nil {
		return [PublicKeySize]byte{}, oops.Wrapf(ErrKeyDerivationFailed, "failed to derive public key: %w", err)
	}
	pubKey, err := privKey.Public()
	if err != nil {
		return [PublicKeySize]byte{}, oops.Wrapf(ErrKeyDerivationFailed, "failed to derive public key: %w", err)
	}

	var pubKeyArray [PublicKeySize]byte
	copy(pubKeyArray[:], pubKey.Bytes())
	return pubKeyArray, nil
}

// performDH performs X25519 Diffie-Hellman key agreement.
func (r *DHRatchet) performDH(privateKey, publicKey []byte) ([]byte, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, oops.Wrapf(ErrInvalidPrivateKeySize, "expected %d, got %d", PrivateKeySize, len(privateKey))
	}
	if len(publicKey) != PublicKeySize {
		return nil, oops.Wrapf(ErrInvalidPublicKeySize, "expected %d, got %d", PublicKeySize, len(publicKey))
	}

	// Perform X25519 DH via the canonical go-i2p/crypto/curve25519 wrapper
	sharedSecret, err := curve25519.SharedKey(privateKey, publicKey)
	if err != nil {
		return nil, oops.Wrapf(ErrDHFailed, "X25519 key agreement failed: %w", err)
	}

	return sharedSecret, nil
}

// Zero securely clears the DH ratchet state from memory.
func (r *DHRatchet) Zero() {
	for i := range r.ourPrivKey {
		r.ourPrivKey[i] = 0
	}
	for i := range r.theirPubKey {
		r.theirPubKey[i] = 0
	}
	for i := range r.rootKey {
		r.rootKey[i] = 0
	}
}
