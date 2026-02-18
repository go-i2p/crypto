package ed25519ph

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"

	"github.com/samber/oops"
)

// Ed25519phSigner provides digital signature creation using the Ed25519ph
// (pre-hashed) variant defined in RFC 8032 Section 5.1.
//
// Unlike PureEdDSA, Ed25519ph first hashes the message with SHA-512, then
// signs the resulting digest with domain separation. This produces signatures
// that are distinct from and incompatible with standard Ed25519 signatures.
type Ed25519phSigner struct {
	k []byte
}

// Sign creates an Ed25519ph digital signature over the provided data.
// The data is first hashed with SHA-512, then signed using Ed25519ph with
// domain separation as specified in RFC 8032 Section 5.1.
// Returns the signature bytes or an error if signing fails.
func (s *Ed25519phSigner) Sign(data []byte) (sig []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Signing data with Ed25519ph")

	if len(s.k) != ed25519.PrivateKeySize {
		log.Error("Invalid Ed25519ph private key size")
		err = oops.Errorf("failed to sign: invalid ed25519ph private key size")
		return
	}

	// Hash the message with SHA-512 as required by Ed25519ph
	h := sha512.Sum512(data)

	// Sign the hash using Ed25519ph (with domain separation)
	sig, err = s.SignHash(h[:])
	return
}

// SignHash creates an Ed25519ph signature over a pre-computed SHA-512 hash.
// The hash must be exactly 64 bytes (SHA-512 output). The signature uses
// Ed25519ph domain separation per RFC 8032 Section 5.1, making it distinct
// from a PureEdDSA signature over the same hash bytes.
func (s *Ed25519phSigner) SignHash(h []byte) (sig []byte, err error) {
	log.WithField("hash_length", len(h)).Debug("Signing hash with Ed25519ph")

	if len(s.k) != ed25519.PrivateKeySize {
		log.Error("Invalid Ed25519ph private key size")
		err = oops.Errorf("failed to sign: invalid ed25519ph private key size")
		return
	}

	// Use Ed25519ph mode via SignWithOptions with Hash: crypto.SHA512
	// This applies the RFC 8032 Ed25519ph domain separation tag
	opts := &ed25519.Options{Hash: crypto.SHA512}
	privKey := ed25519.PrivateKey(s.k)
	sig, err = privKey.Sign(nil, h, opts)
	if err != nil {
		log.WithField("error", err).Error("Ed25519ph signing failed")
		err = oops.Errorf("failed to sign with ed25519ph: %w", err)
		return
	}

	log.WithField("signature_length", len(sig)).Debug("Ed25519ph signature created successfully")
	return
}
