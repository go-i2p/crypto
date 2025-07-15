package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

type RSA2048PrivateKey struct {
	RSA2048PrivateKey [512]byte // I2P-compliant: 256 bytes modulus + 256 bytes private exponent
}

// Sign implements types.Signer.
// Signs data by first hashing it with SHA-256
func (r RSA2048PrivateKey) Sign(data []byte) (sig []byte, err error) {
	// Hash the data with SHA-256 (appropriate for RSA-2048)
	hash := sha256.Sum256(data)
	return r.SignHash(hash[:])
}

// SignHash implements types.Signer.
// Signs a pre-computed hash
func (r RSA2048PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	// Convert byte array to rsa.PrivateKey
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		return nil, oops.Errorf("failed to parse RSA private key: %w", err)
	}

	// Sign the hash with PKCS#1 v1.5
	sig, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h)
	if err != nil {
		return nil, oops.Errorf("failed to sign hash: %w", err)
	}

	log.Debug("RSA-2048 signature created successfully")
	return sig, nil
}

// Bytes implements types.PrivateKey.
// Returns the raw bytes of the private key
func (r RSA2048PrivateKey) Bytes() []byte {
	return r.RSA2048PrivateKey[:]
}

// Public implements types.PrivateKey.
// Extracts the public key from the private key
func (r RSA2048PrivateKey) Public() (types.SigningPublicKey, error) {
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		return nil, oops.Errorf("failed to parse RSA private key: %w", err)
	}

	// Extract public key and convert to bytes
	pubKey := privKey.Public().(*rsa.PublicKey)
	pubBytes := pubKey.N.Bytes()

	// Create and return the RSA2048PublicKey
	var publicKey RSA2048PublicKey
	// Pad with zeros if necessary (big-endian format)
	if len(pubBytes) <= 256 {
		copy(publicKey[256-len(pubBytes):], pubBytes)
	} else {
		copy(publicKey[:], pubBytes[len(pubBytes)-256:])
	}

	log.Debug("RSA-2048 public key extracted successfully")
	return publicKey, nil
}

// Zero implements types.PrivateKey.
// Securely erases key material
func (r *RSA2048PrivateKey) Zero() {
	// Overwrite private key material with zeros
	for i := range r.RSA2048PrivateKey {
		r.RSA2048PrivateKey[i] = 0
	}
	log.Debug("RSA-2048 private key securely erased")
}

// Len implements types.SigningPrivateKey.
func (r RSA2048PrivateKey) Len() int {
	return len(r.RSA2048PrivateKey)
}

// NewSigner implements types.SigningPrivateKey.
func (r RSA2048PrivateKey) NewSigner() (types.Signer, error) {
	return r, nil
}

// Generate implements types.SigningPrivateKey.
func (r RSA2048PrivateKey) Generate() (types.SigningPrivateKey, error) {
	log.Debug("Generating new RSA2048 private key")
	stdPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.WithError(err).Error("Failed to generate RSA2048 key")
		return nil, oops.Errorf("failed to generate RSA2048 key: %w", err)
	}

	// I2P-compliant format: Store modulus (256 bytes) + private exponent (256 bytes)
	var privKey RSA2048PrivateKey

	// Store the modulus (N) - first 256 bytes
	modulusBytes := stdPrivKey.N.Bytes()
	if len(modulusBytes) > 256 {
		return nil, ErrInvalidKeySize
	}
	// Pad with leading zeros if needed
	copy(privKey.RSA2048PrivateKey[256-len(modulusBytes):256], modulusBytes)

	// Store the private exponent (D) - next 256 bytes
	dBytes := stdPrivKey.D.Bytes()
	if len(dBytes) > 256 {
		return nil, ErrInvalidKeySize
	}
	// Pad with leading zeros if needed
	copy(privKey.RSA2048PrivateKey[512-len(dBytes):512], dBytes)

	log.Debug("New RSA2048 private key generated successfully")
	return privKey, nil
}

// Helper method to convert I2P format to rsa.PrivateKey
func (r RSA2048PrivateKey) toRSAPrivateKey() (*rsa.PrivateKey, error) {
	// Extract modulus (N) from first 256 bytes
	nBytes := r.RSA2048PrivateKey[:256]
	n := new(big.Int).SetBytes(nBytes)

	// Extract private exponent (D) from next 256 bytes
	dBytes := r.RSA2048PrivateKey[256:512]
	d := new(big.Int).SetBytes(dBytes)

	// Standard RSA public exponent
	e := 65537

	// Create RSA private key
	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: e,
		},
		D: d,
	}

	// Validate key size is 2048 bits
	if privKey.Size() != 256 {
		return nil, oops.Errorf("unexpected RSA key size: got %d, want 256", privKey.Size())
	}

	return privKey, nil
}

var (
	_ types.PrivateKey = (*RSA2048PrivateKey)(nil)
	_ types.Signer     = RSA2048PrivateKey{}
)
