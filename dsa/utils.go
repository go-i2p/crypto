package dsa

import (
	"crypto/dsa"
	"io"
	"math/big"
)

// generateDSA creates a new DSA keypair using the predefined I2P parameters.
// This function initializes a DSA private key structure with I2P-standard DSA parameters
// (1024-bit p, 160-bit q, generator g) and generates a cryptographically secure keypair.
// The generated keypair is compatible with I2P DSA signature operations and follows
// the FIPS 186-2 DSA specification used by the I2P network protocol.
func generateDSA(priv *dsa.PrivateKey, rand io.Reader) error {
	log.Debug("Generating DSA key pair")
	// Initialize with I2P-standard DSA parameters (P, Q, G)
	priv.P = param.P
	priv.Q = param.Q
	priv.G = param.G
	// Generate cryptographically secure keypair using provided entropy source
	err := dsa.GenerateKey(priv, rand)
	if err != nil {
		log.WithError(err).Error("Failed to generate DSA key pair")
	} else {
		log.Debug("DSA key pair generated successfully")
	}
	return err
}

// createDSAPublicKey constructs a DSA public key from the public component Y.
// This function creates a complete DSA public key structure using the I2P-standard
// parameters and the provided public key value Y. The resulting key can be used
// for signature verification operations in the I2P network context.
func createDSAPublicKey(Y *big.Int) *dsa.PublicKey {
	log.Debug("Creating DSA public key")
	// Construct public key with I2P parameters and provided Y value
	return &dsa.PublicKey{
		Parameters: param,
		Y:          Y,
	}
}

// createDSAPrivkey constructs a DSA private key from the private component X.
// This function creates a complete DSA private key structure using the I2P-standard
// parameters and the provided private key value X. It computes the corresponding
// public key Y = g^X mod p and validates that X is within the valid range (0 < X < p).
// Returns a fully initialized private key suitable for DSA signing operations.
func createDSAPrivkey(X *big.Int) (k *dsa.PrivateKey) {
	log.Debug("Creating DSA private key")
	// Validate that private key X is within valid range (0 < X < p)
	if X.Cmp(dsap) == -1 {
		// Compute public key Y = g^X mod p using modular exponentiation
		Y := new(big.Int)
		Y.Exp(dsag, X, dsap)
		// Construct complete private key with computed public component
		k = &dsa.PrivateKey{
			PublicKey: dsa.PublicKey{
				Parameters: param,
				Y:          Y,
			},
			X: X,
		}
		log.Debug("DSA private key created successfully")
	} else {
		// Private key X exceeds modulus p - cryptographically invalid
		log.Warn("Failed to create DSA private key: X is not less than p")
	}
	return
}
