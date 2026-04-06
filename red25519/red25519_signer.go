package red25519

import (
	"github.com/go-i2p/logger"
	upstream "github.com/go-i2p/red25519"
	"github.com/samber/oops"
)

// Red25519Signer provides digital signature creation using Red25519 (RedDSA).
//
// Red25519 signatures are byte-identical to standard Ed25519 for unblinded keys.
// The signer uses deterministic nonces and supports both normal and blinded private keys.
type Red25519Signer struct {
	k upstream.PrivateKey
}

// Sign creates a Red25519 digital signature over the provided data.
// Returns the 64-byte signature (R || S) or an error if signing fails.
// Supports both normal (64-byte) and blinded (96-byte) private keys.
func (s *Red25519Signer) Sign(data []byte) (sig []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "red25519", "func": "Red25519Signer.Sign", "data_length": len(data)}).Debug("Signing data with Red25519")

	if len(s.k) != PrivateKeySize && len(s.k) != BlindedPrivateKeySize {
		log.WithFields(logger.Fields{"pkg": "red25519", "func": "Red25519Signer.Sign"}).Error("Invalid Red25519 private key size")
		err = oops.Errorf("failed to sign: invalid red25519 private key size")
		return
	}

	sig = upstream.Sign(s.k, data)
	log.WithFields(logger.Fields{"pkg": "red25519", "func": "Red25519Signer.Sign", "signature_length": len(sig)}).Debug("Red25519 signature created successfully")
	return
}

// SignHash creates a Red25519 signature over a pre-computed hash.
// For Red25519, SignHash treats the hash as the message to sign directly.
func (s *Red25519Signer) SignHash(h []byte) (sig []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "red25519", "func": "Red25519Signer.SignHash", "hash_length": len(h)}).Debug("Signing hash with Red25519")
	return s.Sign(h)
}
