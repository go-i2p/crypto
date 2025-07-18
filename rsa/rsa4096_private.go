package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// RSA4096PrivateKey represents a 4096-bit RSA private key in I2P format.
// The key data is stored as a 1024-byte array containing the modulus (512 bytes)
// and private exponent (512 bytes) following I2P cryptographic specifications.
// This type implements types.Signer and provides maximum security in the RSA family.
// RSA-4096 offers equivalent security to 192-bit symmetric encryption.
type RSA4096PrivateKey struct {
	RSA4096PrivateKey [1024]byte // I2P-compliant: 512 bytes modulus + 512 bytes private exponent
}

// Sign implements types.Signer.
// Signs data by first hashing it with SHA-512
func (r RSA4096PrivateKey) Sign(data []byte) (sig []byte, err error) {
	log.Debug("Signing data with RSA-4096")
	// Hash the data with SHA-512 (appropriate for RSA-4096)
	hash := sha512.Sum512(data)
	return r.SignHash(hash[:])
}

// SignHash implements types.Signer.
// Signs a pre-computed hash
func (r RSA4096PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	log.Debug("Signing hash with RSA-4096")

	// Convert I2P format to rsa.PrivateKey
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		log.WithError(err).Error("Failed to parse RSA-4096 private key")
		return nil, oops.Errorf("invalid RSA-4096 private key: %w", err)
	}

	// Sign the hash using PKCS1v15
	sig, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, h)
	if err != nil {
		log.WithError(err).Error("RSA-4096 signature generation failed")
		return nil, oops.Errorf("failed to generate RSA-4096 signature: %w", err)
	}

	log.Debug("RSA-4096 signature generated successfully")
	return sig, nil
}

// Bytes implements types.PrivateKey.
// Returns the raw bytes of the private key
func (r RSA4096PrivateKey) Bytes() []byte {
	log.Debug("Getting RSA-4096 private key bytes")
	return r.RSA4096PrivateKey[:]
}

// Public implements types.PrivateKey.
// Extracts the public key from the private key
func (r RSA4096PrivateKey) Public() (types.SigningPublicKey, error) {
	log.Debug("Extracting public key from RSA-4096 private key")

	// Convert I2P format to standard RSA private key structure
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		log.WithError(err).Error("Failed to parse RSA-4096 private key")
		return nil, oops.Errorf("invalid RSA-4096 private key: %w", err)
	}

	// Get the public key bytes (modulus n) in the correct I2P format
	pubKeyBytes := privKey.N.Bytes()

	// The RSA4096PublicKey is exactly 512 bytes in I2P format
	var pubKey RSA4096PublicKey

	// Ensure proper padding if the modulus has leading zeros for consistent 512-byte size
	copy(pubKey[512-len(pubKeyBytes):], pubKeyBytes)

	log.Debug("RSA-4096 public key extracted successfully")
	return pubKey, nil
}

// Helper method to convert I2P format to rsa.PrivateKey
func (r RSA4096PrivateKey) toRSAPrivateKey() (*rsa.PrivateKey, error) {
	// Extract modulus (N) from first 512 bytes of I2P key format
	nBytes := r.RSA4096PrivateKey[:512]
	n := new(big.Int).SetBytes(nBytes)

	// Extract private exponent (D) from next 512 bytes of I2P key format
	dBytes := r.RSA4096PrivateKey[512:1024]
	d := new(big.Int).SetBytes(dBytes)

	// Standard RSA public exponent as defined in RFC 3447 and used by I2P
	e := 65537

	// Create RSA private key structure compatible with Go's crypto/rsa package
	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: e,
		},
		D: d,
	}

	// Validate key size is exactly 4096 bits (512 bytes) as expected for RSA-4096
	if privKey.Size() != 512 {
		return nil, oops.Errorf("unexpected RSA key size: got %d, want 512", privKey.Size())
	}

	return privKey, nil
}

// Zero implements types.PrivateKey.
// Securely clears the private key from memory
func (r *RSA4096PrivateKey) Zero() {
	log.Debug("Securely clearing RSA-4096 private key from memory")
	// Overwrite the key material with zeros to prevent memory leakage
	// This is critical for security as RSA-4096 keys contain the most sensitive cryptographic material
	for i := range r.RSA4096PrivateKey {
		r.RSA4096PrivateKey[i] = 0
	}
}

// Len implements types.SigningPrivateKey.
func (r RSA4096PrivateKey) Len() int {
	return len(r.RSA4096PrivateKey)
}

// NewSigner implements types.SigningPrivateKey.
func (r RSA4096PrivateKey) NewSigner() (types.Signer, error) {
	return r, nil
}

// Generate implements types.SigningPrivateKey.
func (r RSA4096PrivateKey) Generate() (types.SigningPrivateKey, error) {
	log.Debug("Generating new RSA-4096 private key")
	stdPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.WithError(err).Error("Failed to generate RSA-4096 private key")
		return nil, oops.Errorf("failed to generate RSA-4096 key: %w", err)
	}

	// Convert to our format
	var newKey RSA4096PrivateKey

	// Extract modulus (512 bytes for RSA-4096)
	nBytes := stdPrivKey.N.Bytes()
	if len(nBytes) <= 512 {
		copy(newKey.RSA4096PrivateKey[512-len(nBytes):512], nBytes)
	} else {
		copy(newKey.RSA4096PrivateKey[:512], nBytes[len(nBytes)-512:])
	}

	// Extract private exponent (512 bytes for RSA-4096)
	dBytes := stdPrivKey.D.Bytes()
	if len(dBytes) <= 512 {
		copy(newKey.RSA4096PrivateKey[1024-len(dBytes):], dBytes)
	} else {
		copy(newKey.RSA4096PrivateKey[512:], dBytes[len(dBytes)-512:])
	}

	log.Debug("New RSA-4096 private key generated successfully")
	return newKey, nil
}

var (
	_ types.PrivateKey = (*RSA4096PrivateKey)(nil)
	_ types.Signer     = RSA4096PrivateKey{}
)
