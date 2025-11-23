// Package ecies key derivation functions for ECIES-X25519-AEAD-Ratchet protocol.
package ecies

import (
	"crypto/subtle"
	"time"

	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

// DeriveSessionKeys derives the initial session keys from a shared secret.
// This is used during session establishment to derive:
// - Sending chain key (32 bytes)
// - Receiving chain key (32 bytes)
// Returns (sendKey, recvKey, error)
func DeriveSessionKeys(sharedSecret, info []byte) ([32]byte, [32]byte, error) {
	if len(sharedSecret) == 0 {
		return [32]byte{}, [32]byte{}, oops.Errorf("shared secret cannot be empty")
	}

	// Use kdf package for consistent key derivation
	var sharedSecretArray [32]byte
	copy(sharedSecretArray[:], sharedSecret)
	kd := kdf.NewKeyDerivation(sharedSecretArray)

	// Derive 64 bytes: sendKey (32) + recvKey (32)
	keys, err := kd.DeriveKeys(info, 2)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}

	log.Debug("Session keys derived successfully")
	return keys[0], keys[1], nil
}

// DeriveMessageKey derives a message encryption key from a chain key.
// This is used by the symmetric key ratchet.
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
	messageKey, err := ratchetInstance.DeriveMessageKey(messageNumber)
	if err != nil {
		return [32]byte{}, err
	}

	return messageKey, nil
}

// DeriveSessionTag derives a session tag from a chain key.
// This is used by the session tag ratchet.
// chainKey: The current chain key (32 bytes)
// tagNumber: The tag sequence number
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

// DeriveNoiseKeys derives keys using the Noise protocol pattern.
// This is specifically for ECIES session establishment following Noise_X pattern.
// sharedSecret: Output from X25519 DH
// info: Context string for domain separation
// Returns (sendKey, recvKey, chainKey, error)
func DeriveNoiseKeys(sharedSecret, info []byte) ([32]byte, [32]byte, [32]byte, error) {
	if len(sharedSecret) == 0 {
		return [32]byte{}, [32]byte{}, [32]byte{}, oops.Errorf("shared secret cannot be empty")
	}

	// Use kdf package for consistent key derivation
	var sharedSecretArray [32]byte
	copy(sharedSecretArray[:], sharedSecret)
	kd := kdf.NewKeyDerivation(sharedSecretArray)

	// Derive 96 bytes: sendKey (32) + recvKey (32) + chainKey (32)
	keys, err := kd.DeriveKeys(info, 3)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, err
	}

	log.Debug("Noise keys derived successfully")
	return keys[0], keys[1], keys[2], nil
}

// DeriveChaCha20Key derives a ChaCha20 encryption key from a message key.
// Some implementations may need this extra derivation step.
func DeriveChaCha20Key(messageKey [32]byte) ([32]byte, error) {
	// For now, use the message key directly as ChaCha20 uses 256-bit keys
	// In some variants, you might want to derive it:
	// keys, err := deriveKeys(messageKey[:], []byte("ChaCha20-Key"), 32)
	return messageKey, nil
}

// DeriveChaCha20Nonce derives a ChaCha20 nonce from a message key and message number.
// Returns a 12-byte nonce suitable for ChaCha20-Poly1305.
func DeriveChaCha20Nonce(messageKey [32]byte, messageNum uint32) ([12]byte, error) {
	// Use kdf package for consistent derivation
	kd := kdf.NewKeyDerivation(messageKey)

	// For nonce derivation, we only need 12 bytes (not a full 32-byte key)
	// DeriveKeys returns [][32]byte, so we get one key and take first 12 bytes
	keys, err := kd.DeriveKeys([]byte("ChaCha20-Nonce"), 1)
	if err != nil {
		return [12]byte{}, err
	}

	// Take first 12 bytes for the nonce
	var nonce [12]byte
	copy(nonce[:], keys[0][:12])
	return nonce, nil
}
