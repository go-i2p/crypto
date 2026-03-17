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
	// ECP521PrivateKey represents a P-521 ECDSA private key.
	//
	// CRITICAL: Never create ECP521PrivateKey using zero-value construction (e.g. var key ECP521PrivateKey).
	// Zero-value construction results in an all-zero key which:
	//   - Is cryptographically invalid
	//   - Will panic when calling Public()
	//   - Violates ECDSA security requirements
	//
	// ALWAYS use NewECP521PrivateKey() for safe construction.
	ECP521PrivateKey [66]byte
)

// NewECP521PrivateKey creates a new P-521 ECDSA private key from bytes with validation.
//
// This constructor provides mandatory validation to prevent common security issues:
//   - Rejects inputs that are not exactly 66 bytes
//   - Rejects all-zero keys (cryptographically invalid)
//   - Returns defensive copy to prevent external mutation
//
// Use this instead of direct byte slice conversion to ensure key validity.
//
// Returns an error if:
//   - Input is not exactly 66 bytes
//   - Input is all zeros (invalid ECDSA private key)
func NewECP521PrivateKey(data []byte) (*ECP521PrivateKey, error) {
	if len(data) != 66 {
		return nil, oops.Errorf("invalid P-521 private key size: expected 66 bytes, got %d bytes", len(data))
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
		return nil, oops.Errorf("invalid P-521 private key: cannot be all zeros")
	}

	var key ECP521PrivateKey
	copy(key[:], data)
	return &key, nil
}

// Len implements types.SigningPrivateKey.
func (e *ECP521PrivateKey) Len() int {
	return 66
}

// Sign implements types.Signer.
func (e *ECP521PrivateKey) Sign(data []byte) (sig []byte, err error) {
	hash := sha512.Sum512(data)
	return e.SignHash(hash[:])
}

// SignHash implements types.Signer.
func (e *ECP521PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	curve := elliptic.P521()
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

	sig = make([]byte, 132)
	copy(sig[66-len(sigR):66], sigR)
	copy(sig[132-len(sigS):], sigS)

	log.Debug("Generated ECDSA-P521 signature")
	return sig, nil
}

// Decrypt implements types.Decrypter.
func (e *ECP521PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return nil, oops.Errorf("decryption not supported with ECDSA keys")
}

// Bytes implements types.PrivateKey.
func (e *ECP521PrivateKey) Bytes() []byte {
	return e[:]
}

// Public implements types.PrivateKey.
func (e *ECP521PrivateKey) Public() (types.SigningPublicKey, error) {
	curve := elliptic.P521()
	x, y := curve.ScalarBaseMult(e[:])
	if x == nil || y == nil {
		return nil, oops.Errorf("failed to generate public key from private key")
	}

	publicKey := ECP521PublicKey{}
	xBytes := x.Bytes()
	yBytes := y.Bytes()

	copy(publicKey[66-len(xBytes):66], xBytes)
	copy(publicKey[132-len(yBytes):], yBytes)

	log.Debug("Generated ECDSA-P521 public key from private key")
	return publicKey, nil
}

// Zero implements types.PrivateKey.
func (e *ECP521PrivateKey) Zero() {
	for i := range e {
		e[i] = 0
	}
	log.Debug("Zeroed ECDSA-P521 private key")
}

// Generate implements SigningPrivateKey.Generate
func (e *ECP521PrivateKey) Generate() (types.SigningPrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate ECDSA-P521 key: %w", err)
	}

	result := &ECP521PrivateKey{}
	dBytes := privateKey.D.Bytes()
	copy(result[66-len(dBytes):], dBytes)

	log.Debug("Generated new ECDSA-P521 private key")
	return result, nil
}

// NewSigner implements SigningPrivateKey.NewSigner
func (e *ECP521PrivateKey) NewSigner() (types.Signer, error) {
	return e, nil
}
