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
	// Validate that the provided key data matches the expected size for the RSA variant
	if len(data) != expectedSize {
		return nil, fmt.Errorf("invalid RSA public key length: expected %d, got %d",
			expectedSize, len(data))
	}
	// Use standard RSA public exponent 65537 as defined in RFC 3447 and I2P specifications
	e := int(65537)

	// Convert raw key bytes to big integer for RSA modulus (N)
	// The modulus is the full key in I2P format
	n := new(big.Int).SetBytes(data)

	// Construct Go crypto/rsa compatible public key structure
	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	return pubKey, nil
}

// GenerateRSA2048KeyPair generates a new RSA-2048 key pair for I2P cryptographic operations.
// Returns a public key for verification and a private key for signing operations.
// RSA-2048 provides 112-bit equivalent security and is suitable for most I2P applications.
// The generated keys follow I2P's standard byte array format for compatibility.
// Example usage: pubKey, privKey, err := GenerateRSA2048KeyPair()
func GenerateRSA2048KeyPair() (*RSA2048PublicKey, *RSA2048PrivateKey, error) {
	log.Debug("Generating RSA-2048 key pair")

	var privKey RSA2048PrivateKey
	// Generate the private key using the type's Generate method which ensures I2P compliance
	generatedPrivKey, err := privKey.Generate()
	if err != nil {
		log.WithError(err).Error("Failed to generate RSA-2048 private key")
		return nil, nil, err
	}

	// Type assertion to ensure the generated key is the correct RSA-2048 type
	rsaPrivKey := generatedPrivKey.(RSA2048PrivateKey)
	// Extract the corresponding public key from the generated private key
	pubKey, err := rsaPrivKey.Public()
	if err != nil {
		log.WithError(err).Error("Failed to extract RSA-2048 public key")
		return nil, nil, err
	}

	// Type assertion to ensure the extracted public key is the correct RSA-2048 type
	rsaPubKey := pubKey.(RSA2048PublicKey)
	log.Debug("RSA-2048 key pair generated successfully")
	return &rsaPubKey, &rsaPrivKey, nil
}

// GenerateRSA3072KeyPair generates a new RSA-3072 key pair for enhanced I2P security.
// Returns a public key for verification and a private key for signing operations.
// RSA-3072 provides 128-bit equivalent security, suitable for high-security I2P applications.
// The generated keys follow I2P's standard byte array format for network compatibility.
// Example usage: pubKey, privKey, err := GenerateRSA3072KeyPair()
func GenerateRSA3072KeyPair() (*RSA3072PublicKey, *RSA3072PrivateKey, error) {
	log.Debug("Generating RSA-3072 key pair")

	var privKey RSA3072PrivateKey
	// Generate the private key using the type's Generate method for I2P format compliance
	generatedPrivKey, err := privKey.Generate()
	if err != nil {
		log.WithError(err).Error("Failed to generate RSA-3072 private key")
		return nil, nil, err
	}

	// Type assertion with pointer dereference for RSA-3072 key structure
	rsaPrivKey := generatedPrivKey.(*RSA3072PrivateKey)
	// Extract the corresponding public key from the generated private key
	pubKey, err := rsaPrivKey.Public()
	if err != nil {
		log.WithError(err).Error("Failed to extract RSA-3072 public key")
		return nil, nil, err
	}

	// Type assertion to ensure the extracted public key is the correct RSA-3072 type
	rsaPubKey := pubKey.(RSA3072PublicKey)
	log.Debug("RSA-3072 key pair generated successfully")
	return &rsaPubKey, rsaPrivKey, nil
}

// GenerateRSA4096KeyPair generates a new RSA-4096 key pair for maximum I2P security.
// Returns a public key for verification and a private key for signing operations.
// RSA-4096 provides 192-bit equivalent security, the highest security level in the RSA family.
// The generated keys follow I2P's standard byte array format for network interoperability.
// Example usage: pubKey, privKey, err := GenerateRSA4096KeyPair()
func GenerateRSA4096KeyPair() (*RSA4096PublicKey, *RSA4096PrivateKey, error) {
	log.Debug("Generating RSA-4096 key pair")

	var privKey RSA4096PrivateKey
	// Generate the private key using the type's Generate method for maximum security I2P compliance
	generatedPrivKey, err := privKey.Generate()
	if err != nil {
		log.WithError(err).Error("Failed to generate RSA-4096 private key")
		return nil, nil, err
	}

	// Type assertion to ensure the generated key is the correct RSA-4096 type
	rsaPrivKey := generatedPrivKey.(RSA4096PrivateKey)
	// Extract the corresponding public key from the generated private key
	pubKey, err := rsaPrivKey.Public()
	if err != nil {
		log.WithError(err).Error("Failed to extract RSA-4096 public key")
		return nil, nil, err
	}

	// Type assertion to ensure the extracted public key is the correct RSA-4096 type
	rsaPubKey := pubKey.(RSA4096PublicKey)
	log.Debug("RSA-4096 key pair generated successfully")
	return &rsaPubKey, &rsaPrivKey, nil
}
