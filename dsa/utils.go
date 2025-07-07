package dsa

import (
	"crypto/dsa"
	"io"
	"math/big"
)

// generateDSA generates a DSA keypair using the predefined I2P parameters.
// Moved from: dsa.go
func generateDSA(priv *dsa.PrivateKey, rand io.Reader) error {
	log.Debug("Generating DSA key pair")
	// put our paramters in
	priv.P = param.P
	priv.Q = param.Q
	priv.G = param.G
	// generate the keypair
	err := dsa.GenerateKey(priv, rand)
	if err != nil {
		log.WithError(err).Error("Failed to generate DSA key pair")
	} else {
		log.Debug("DSA key pair generated successfully")
	}
	return err
}

// createDSAPublicKey creates an I2P DSA public key given its public component.
// Moved from: dsa.go
func createDSAPublicKey(Y *big.Int) *dsa.PublicKey {
	log.Debug("Creating DSA public key")
	return &dsa.PublicKey{
		Parameters: param,
		Y:          Y,
	}
}

// createDSAPrivkey creates an I2P DSA private key given its private component.
// Moved from: dsa.go
func createDSAPrivkey(X *big.Int) (k *dsa.PrivateKey) {
	log.Debug("Creating DSA private key")
	if X.Cmp(dsap) == -1 {
		Y := new(big.Int)
		Y.Exp(dsag, X, dsap)
		k = &dsa.PrivateKey{
			PublicKey: dsa.PublicKey{
				Parameters: param,
				Y:          Y,
			},
			X: X,
		}
		log.Debug("DSA private key created successfully")
	} else {
		log.Warn("Failed to create DSA private key: X is not less than p")
	}
	return
}
