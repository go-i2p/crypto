package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type (
	// RSA3072PublicKey represents a 3072-bit RSA public key in I2P format.
	// The key is stored as a 384-byte array containing the public key modulus.
	// This type implements types.Verifier for signature verification with enhanced security.
	// RSA-3072 provides equivalent security to 128-bit symmetric encryption.
	RSA3072PublicKey [384]byte
)

// Verify implements types.Verifier.
func (r RSA3072PublicKey) Verify(data []byte, sig []byte) error {
	// Hash the data with SHA512 (commonly used with RSA3072 in I2P)
	hash := sha512.Sum512(data)
	return r.VerifyHash(hash[:], sig)
}

// VerifyHash implements types.Verifier.
func (r RSA3072PublicKey) VerifyHash(h []byte, sig []byte) error {
	// Convert I2P byte format to standard RSA public key structure
	pubKey, err := rsaPublicKeyFromBytes(r[:], 384)
	if err != nil {
		return oops.Errorf("failed to parse RSA3072 public key: %w", err)
	}

	// For RSA3072, SHA512 is often used as per I2P enhanced security specifications
	hashed := h
	if len(h) != sha512.Size {
		return oops.Errorf("RSA3072 verification requires SHA-512 hash (expected %d bytes, got %d)",
			sha512.Size, len(h))
	}

	// Perform PKCS#1 v1.5 signature verification using Go's crypto/rsa with SHA-512
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, hashed, sig)
	if err != nil {
		return oops.Errorf("RSA signature verification failed: %w", err)
	}

	return nil
}

// Bytes implements SigningPublicKey.
func (r RSA3072PublicKey) Bytes() []byte {
	return r[:]
}

// Len implements SigningPublicKey.
func (r RSA3072PublicKey) Len() int {
	return len(r)
}

// NewVerifier implements SigningPublicKey.
func (r RSA3072PublicKey) NewVerifier() (types.Verifier, error) {
	// The RSA3072PublicKey itself implements the Verifier interface
	return r, nil
}

var (
	_ types.PublicKey = RSA3072PublicKey{}
	_ types.Verifier  = RSA3072PublicKey{}
)
