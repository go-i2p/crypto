package ed25519

import (
	"crypto/ed25519"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Ed25519Signer provides digital signature creation using Ed25519 private keys.
// This type implements the Signer interface for generating cryptographic signatures
// over arbitrary data using the Ed25519 signature algorithm from RFC 8032.
type Ed25519Signer struct {
	k []byte
}

// Sign creates an Ed25519 digital signature over the provided data.
// The data is passed directly to ed25519.Sign which implements PureEdDSA
// (RFC 8032) and performs its own internal SHA-512 hashing.
// Returns the signature bytes or an error if signing fails.
func (s *Ed25519Signer) Sign(data []byte) (sig []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ed25519", "func": "Ed25519Signer.Sign", "data_length": len(data)}).Debug("Signing data with Ed25519")

	// Validate private key size before attempting signature generation
	if len(s.k) != ed25519.PrivateKeySize {
		log.WithFields(logger.Fields{"pkg": "ed25519", "func": "Ed25519Signer.Sign"}).Error("Invalid Ed25519 private key size")
		err = oops.Errorf("failed to sign: invalid ed25519 private key size")
		return sig, err
	}
	// Sign the data directly — ed25519.Sign implements PureEdDSA (RFC 8032)
	// which performs its own internal SHA-512 hashing
	sig = ed25519.Sign(s.k, data)
	return sig, err
}

// SignHash creates an Ed25519 signature over a pre-computed hash.
// This method signs the provided hash directly without additional hashing.
// The hash should typically be a SHA-512 digest for Ed25519 compatibility.
func (s *Ed25519Signer) SignHash(h []byte) (sig []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ed25519", "func": "Ed25519Signer.SignHash", "hash_length": len(h)}).Debug("Signing hash with Ed25519")
	// Generate Ed25519 signature using the standard library implementation
	sig = ed25519.Sign(s.k, h)
	log.WithFields(logger.Fields{"pkg": "ed25519", "func": "Ed25519Signer.SignHash", "signature_length": len(sig)}).Debug("Ed25519 signature created successfully")
	return sig, err
}
