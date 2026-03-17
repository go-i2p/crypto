package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type (
	// ECP384PrivateKey represents a P-384 ECDSA private key.
	//
	// CRITICAL: Never create ECP384PrivateKey using zero-value construction (e.g. var key ECP384PrivateKey).
	// Zero-value construction results in an all-zero key which:
	//   - Is cryptographically invalid
	//   - Will panic when calling Public()
	//   - Violates ECDSA security requirements
	//
	// ALWAYS use NewECP384PrivateKey() for safe construction.
	ECP384PrivateKey [48]byte
)

// NewECP384PrivateKey creates a new P-384 ECDSA private key from bytes with validation.
//
// This constructor provides mandatory validation to prevent common security issues:
//   - Rejects inputs that are not exactly 48 bytes
//   - Rejects all-zero keys (cryptographically invalid)
//   - Returns defensive copy to prevent external mutation
//
// Use this instead of direct byte slice conversion to ensure key validity.
//
// Returns an error if:
//   - Input is not exactly 48 bytes
//   - Input is all zeros (invalid ECDSA private key)
func NewECP384PrivateKey(data []byte) (*ECP384PrivateKey, error) {
	if len(data) != 48 {
		return nil, oops.Errorf("invalid P-384 private key size: expected 48 bytes, got %d bytes", len(data))
	}

	// Check for all-zero key (cryptographically invalid)
	isZero := true
	for _, b := range data {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return nil, oops.Errorf("invalid P-384 private key: cannot be all zeros")
	}

	var key ECP384PrivateKey
	copy(key[:], data)
	return &key, nil
}

// Len implements types.SigningPrivateKey.
func (e *ECP384PrivateKey) Len() int {
	return 48
}

// Sign implements types.Signer.
func (e *ECP384PrivateKey) Sign(data []byte) (sig []byte, err error) {
	hash := sha512.Sum384(data)
	return e.SignHash(hash[:])
}

// SignHash implements types.Signer.
func (e *ECP384PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	curve := elliptic.P384()
	privateKey := new(ecdsa.PrivateKey)
	privateKey.PublicKey.Curve = curve
	privateKey.D = new(big.Int).SetBytes(e[:])
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(e[:])

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h)
	if err != nil {
		return nil, oops.Errorf("failed to sign hash: %w", err)
	}

	sigR := r.Bytes()
	sigS := s.Bytes()

	sig = make([]byte, 96)
	copy(sig[48-len(sigR):48], sigR)
	copy(sig[96-len(sigS):], sigS)

	log.Debug("Generated ECDSA-P384 signature")
	return sig, nil
}

// Decrypt implements types.Decrypter.
func (e *ECP384PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return nil, oops.Errorf("decryption not supported with ECDSA keys")
}

// Bytes implements types.PrivateKey.
func (e *ECP384PrivateKey) Bytes() []byte {
	return e[:]
}

// Public implements types.PrivateKey.
func (e *ECP384PrivateKey) Public() (types.SigningPublicKey, error) {
	curve := elliptic.P384()
	x, y := curve.ScalarBaseMult(e[:])
	if x == nil || y == nil {
		return nil, oops.Errorf("failed to generate public key from private key")
	}

	publicKey := ECP384PublicKey{}
	xBytes := x.Bytes()
	yBytes := y.Bytes()

	copy(publicKey[48-len(xBytes):48], xBytes)
	copy(publicKey[96-len(yBytes):], yBytes)

	log.Debug("Generated ECDSA-P384 public key from private key")
	return publicKey, nil
}

// Zero implements types.PrivateKey.
func (e *ECP384PrivateKey) Zero() {
	for i := range e {
		e[i] = 0
	}
	log.Debug("Zeroed ECDSA-P384 private key")
}

// Generate implements SigningPrivateKey.Generate
func (e *ECP384PrivateKey) Generate() (types.SigningPrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate ECDSA-P384 key: %w", err)
	}

	result := &ECP384PrivateKey{}
	dBytes := privateKey.D.Bytes()
	copy(result[48-len(dBytes):], dBytes)

	log.Debug("Generated new ECDSA-P384 private key")
	return result, nil
}

// NewSigner implements SigningPrivateKey.NewSigner
func (e *ECP384PrivateKey) NewSigner() (types.Signer, error) {
	return e, nil
}
