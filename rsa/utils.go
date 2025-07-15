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

// GenerateRSA2048KeyPair generates a new RSA-2048 key pair
func GenerateRSA2048KeyPair() (*RSA2048PublicKey, *RSA2048PrivateKey, error) {
	log.Debug("Generating RSA-2048 key pair")

	var privKey RSA2048PrivateKey
	generatedPrivKey, err := privKey.Generate()
	if err != nil {
		log.WithError(err).Error("Failed to generate RSA-2048 private key")
		return nil, nil, err
	}

	rsaPrivKey := generatedPrivKey.(RSA2048PrivateKey)
	pubKey, err := rsaPrivKey.Public()
	if err != nil {
		log.WithError(err).Error("Failed to extract RSA-2048 public key")
		return nil, nil, err
	}

	rsaPubKey := pubKey.(RSA2048PublicKey)
	log.Debug("RSA-2048 key pair generated successfully")
	return &rsaPubKey, &rsaPrivKey, nil
}

// GenerateRSA3072KeyPair generates a new RSA-3072 key pair
func GenerateRSA3072KeyPair() (*RSA3072PublicKey, *RSA3072PrivateKey, error) {
	log.Debug("Generating RSA-3072 key pair")

	var privKey RSA3072PrivateKey
	generatedPrivKey, err := privKey.Generate()
	if err != nil {
		log.WithError(err).Error("Failed to generate RSA-3072 private key")
		return nil, nil, err
	}

	rsaPrivKey := generatedPrivKey.(*RSA3072PrivateKey)
	pubKey, err := rsaPrivKey.Public()
	if err != nil {
		log.WithError(err).Error("Failed to extract RSA-3072 public key")
		return nil, nil, err
	}

	rsaPubKey := pubKey.(RSA3072PublicKey)
	log.Debug("RSA-3072 key pair generated successfully")
	return &rsaPubKey, rsaPrivKey, nil
}

// GenerateRSA4096KeyPair generates a new RSA-4096 key pair
func GenerateRSA4096KeyPair() (*RSA4096PublicKey, *RSA4096PrivateKey, error) {
	log.Debug("Generating RSA-4096 key pair")

	var privKey RSA4096PrivateKey
	generatedPrivKey, err := privKey.Generate()
	if err != nil {
		log.WithError(err).Error("Failed to generate RSA-4096 private key")
		return nil, nil, err
	}

	rsaPrivKey := generatedPrivKey.(RSA4096PrivateKey)
	pubKey, err := rsaPrivKey.Public()
	if err != nil {
		log.WithError(err).Error("Failed to extract RSA-4096 public key")
		return nil, nil, err
	}

	rsaPubKey := pubKey.(RSA4096PublicKey)
	log.Debug("RSA-4096 key pair generated successfully")
	return &rsaPubKey, &rsaPrivKey, nil
}
