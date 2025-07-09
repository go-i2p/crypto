package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type (
	RSA4096PublicKey [512]byte
)

// Verify implements types.Verifier.
// This method hashes the data with SHA-512 and verifies the signature
func (r RSA4096PublicKey) Verify(data []byte, sig []byte) error {
	log.Debug("Verifying RSA-4096 signature")
	// Hash the data with SHA-512 (appropriate for RSA-4096)
	hash := sha512.Sum512(data)
	return r.VerifyHash(hash[:], sig)
}

// VerifyHash implements types.Verifier.
// This method verifies a pre-computed hash against the signature
func (r RSA4096PublicKey) VerifyHash(h []byte, sig []byte) error {
	log.Debug("Verifying RSA-4096 signature with pre-computed hash")
	pubKey, err := rsaPublicKeyFromBytes(r[:], 512)
	if err != nil {
		log.WithError(err).Error("Failed to parse RSA-4096 public key")
		return oops.Errorf("invalid RSA-4096 public key: %w", err)
	}

	// For RSA4096, we use SHA-512
	if len(h) != sha512.Size {
		return oops.Errorf("RSA4096 verification requires SHA-512 hash (expected %d bytes, got %d)",
			sha512.Size, len(h))
	}

	// Verify the signature using PKCS1v15
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, h, sig)
	if err != nil {
		return oops.Errorf("RSA signature verification failed: %w", err)
	}

	log.Debug("RSA-4096 signature verified successfully")
	return nil
}

// Bytes implements SigningPublicKey.
// Returns the raw bytes of the public key
func (r RSA4096PublicKey) Bytes() []byte {
	return r[:]
}

// Len implements SigningPublicKey.
// Returns the length of the public key in bytes
func (r RSA4096PublicKey) Len() int {
	return len(r)
}

// NewVerifier implements SigningPublicKey.
// Creates a new verifier instance for this public key
func (r RSA4096PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new RSA-4096 verifier")
	return r, nil
}

var (
	_ types.PublicKey = RSA4096PublicKey{}
	_ types.Verifier  = RSA4096PublicKey{}
)
