// Package ratchet implements cryptographic ratcheting mechanisms for I2P protocols.
//
// This package provides three types of ratchets used in modern I2P encryption:
// 1. Session Tag Ratchet - Derives unique session tags for message routing
// 2. Symmetric Key Ratchet - Derives message encryption keys with forward secrecy
// 3. DH Ratchet - Provides forward secrecy through ephemeral key exchanges
//
// The ratcheting mechanisms are used by ECIES-X25519-AEAD-Ratchet and other
// I2P protocols requiring forward secrecy and secure key derivation.
package ratchet

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Logger instance for ratchet package operations
var log = logger.GetGoI2PLogger()

// Constants for ratchet operations
const (
	// ChainKeySize is the size of chain keys in bytes
	ChainKeySize = 32
	// SessionTagSize is the size of session tags in bytes
	SessionTagSize = 8
	// MessageKeySize is the size of message keys in bytes
	MessageKeySize = 32
	// PublicKeySize is the size of X25519 public keys in bytes
	PublicKeySize = 32
	// PrivateKeySize is the size of X25519 private keys in bytes
	PrivateKeySize = 32
)

// Error constants for ratchet operations
var (
	ErrInvalidChainKeySize   = oops.Errorf("invalid chain key size")
	ErrInvalidPublicKeySize  = oops.Errorf("invalid public key size")
	ErrInvalidPrivateKeySize = oops.Errorf("invalid private key size")
	ErrTagDerivationFailed   = oops.Errorf("session tag derivation failed")
	ErrKeyDerivationFailed   = oops.Errorf("key derivation failed")
	ErrDHFailed              = oops.Errorf("Diffie-Hellman exchange failed")
)
