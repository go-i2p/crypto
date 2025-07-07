package rsa

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

// rsaPublicKeyFromBytes converts raw bytes to an rsa.PublicKey.
// This utility function validates the key length and constructs an RSA public key
// with the standard I2P exponent (65537).
// Moved from: rsa.go
func rsaPublicKeyFromBytes(data []byte, expectedSize int) (*rsa.PublicKey, error) {
	if len(data) != expectedSize {
		return nil, fmt.Errorf("invalid RSA public key length: expected %d, got %d",
			expectedSize, len(data))
	}
	e := int(65537)

	// The modulus is the full key
	n := new(big.Int).SetBytes(data)

	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	return pubKey, nil
}
