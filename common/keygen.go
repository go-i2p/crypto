// Package common provides shared helper functions used across multiple
// cryptographic sub-packages to eliminate code duplication. This package
// is a leaf dependency and must not import other project packages.
package common

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// GenerateKeyPair generates a cryptographic key pair using the provided
// generation function, logging the operation with the given algorithm name.
// It returns raw public and private key bytes for the caller to convert
// to package-specific types. This consolidates the duplicated key generation
// pattern shared by ed25519, ed25519ph, and red25519 packages.
func GenerateKeyPair(name string, genFunc func() ([]byte, []byte, error), log *logger.Logger) ([]byte, []byte, error) {
	log.Debug("Generating " + name + " key pair")

	pubKeyRaw, privKeyRaw, err := genFunc()
	if err != nil {
		return nil, nil, oops.Errorf("failed to generate %s key pair: %w", name, err)
	}

	log.WithField("pubkey_len", len(pubKeyRaw)).
		WithField("privkey_len", len(privKeyRaw)).
		Debug(name + " key pair generated successfully")

	return pubKeyRaw, privKeyRaw, nil
}
