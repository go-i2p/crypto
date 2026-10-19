// Package kdf derives the keys that I2P needs from shared secrets.
//
// # What this package does
//
// In I2P, two routers first agree on one shared secret (for example, through
// an X25519 key exchange). From that single secret the protocol needs many
// different keys: one for a tunnel, one for message encryption, one for
// session tags, and so on. This package derives those keys in a consistent
// way.
//
// [StandardHKDF] is the canonical one-shot RFC 5869 HKDF-SHA256 wrapper used
// across the crypto layer. The I2P ECIES spec defines its HKDF as
// HKDF(salt, ikm, info, n) with a 32-byte salt, so callers pass the arguments
// in that order:
//
//	keydata, err := kdf.StandardHKDF(salt, ikm, []byte("SymmetricRatchet"), 64)
//
// The spec-mandated info strings ("KDFDHRatchetStep", "TagAndKeyGenKeys",
// "STInitialization", "SessionTagKeyGen", "SymmetricRatchet",
// "XDHRatchetTagSet", "SessionReplyTags", "AttachPayloadKDF", ...) are supplied
// by the callers that implement those protocols; see crypto/ratchet and
// go-noise.
//
// Destination blinding has its own conformant KDF, [DeriveBlindingFactorI2P],
// in blinding.go.
//
// # Security considerations
//
//   - Generate root secrets from a cryptographically secure random source.
//   - Pass the spec's exact salt/ikm/info values; do not invent replacements,
//     or the result will not interoperate with other I2P implementations.
//   - Keep each derived key unique to its purpose and context.
package kdf

import (
	"github.com/go-i2p/crypto/hkdf"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Package-level logger
var log = logger.GetGoI2PLogger()

// StandardHKDF performs a one-shot RFC 5869 HKDF-SHA256 key derivation.
// This is the canonical implementation of raw HKDF extract-and-expand in the
// crypto layer, replacing ad-hoc inline implementations found in higher-level
// packages (e.g., noise handshakes, NTCP2).
//
// Parameters:
//   - salt: Optional salt value (can be nil; HKDF will use a zero-filled salt)
//   - ikm: Input key material (must not be empty)
//   - info: Optional context/application-specific info (can be nil)
//   - length: Desired output length in bytes (must be > 0; max 255*32 per RFC 5869)
//
// Returns:
//   - []byte: Derived key material of the requested length
//   - error: Any error during derivation
//
// Example usage:
//
//	derived, err := kdf.StandardHKDF(salt, sharedSecret, []byte("NTCP2-KDF"), 32)
//	if err != nil {
//	    return err
//	}
func StandardHKDF(salt, ikm, info []byte, length int) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "kdf", "func": "StandardHKDF", "ikm_length": len(ikm), "salt_length": len(salt), "info_length": len(info), "output_length": length}).Debug("StandardHKDF derivation")

	deriver := hkdf.NewHKDF()
	derived, err := deriver.Derive(ikm, salt, info, length)
	if err != nil {
		return nil, oops.Wrapf(err, "StandardHKDF derivation failed")
	}

	log.WithFields(logger.Fields{"pkg": "kdf", "func": "StandardHKDF", "derived_length": len(derived)}).Debug("StandardHKDF derivation successful")
	return derived, nil
}
