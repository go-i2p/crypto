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

type RSA3072PrivateKey struct {
	RSA3072PrivateKey [768]byte // I2P-compliant: 384 bytes modulus + 384 bytes private exponent
}

// Len implements types.SigningPrivateKey.
func (r *RSA3072PrivateKey) Len() int {
	return len(r.RSA3072PrivateKey)
}

// NewSigner implements types.SigningPrivateKey.
func (r *RSA3072PrivateKey) NewSigner() (types.Signer, error) {
	return r, nil
}

// Sign implements types.Signer - signs data with SHA512 hash
func (r RSA3072PrivateKey) Sign(data []byte) (sig []byte, err error) {
	// Hash the data with SHA-512 which is appropriate for RSA-3072
	hash := sha512.Sum512(data)
	return r.SignHash(hash[:])
}

// SignHash implements types.Signer - signs a pre-computed hash
func (r RSA3072PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	// Convert byte array to rsa.PrivateKey
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		return nil, oops.Errorf("failed to parse RSA private key: %w", err)
	}

	// Sign the hash with PKCS#1 v1.5
	sig, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, h)
	if err != nil {
		return nil, oops.Errorf("failed to sign hash: %w", err)
	}

	log.Debug("RSA-3072 signature created successfully")
	return sig, nil
}

// Bytes implements types.PrivateKey - returns raw key bytes
func (r RSA3072PrivateKey) Bytes() []byte {
	return r.RSA3072PrivateKey[:]
}

// Public implements types.PrivateKey - derives public key from private key
func (r RSA3072PrivateKey) Public() (types.SigningPublicKey, error) {
	// Convert byte array to rsa.PrivateKey
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		return nil, oops.Errorf("failed to parse RSA private key: %w", err)
	}

	// Extract public key and convert to bytes
	pubKey := privKey.Public().(*rsa.PublicKey)
	pubBytes := pubKey.N.Bytes()

	// Create and return the RSA3072PublicKey
	var publicKey RSA3072PublicKey
	// Pad with zeros if necessary (big-endian format)
	if len(pubBytes) <= 384 {
		copy(publicKey[384-len(pubBytes):], pubBytes)
	} else {
		copy(publicKey[:], pubBytes[len(pubBytes)-384:])
	}

	log.Debug("RSA-3072 public key derived successfully")
	return publicKey, nil
}

// Zero implements types.PrivateKey - securely erases key material
func (r *RSA3072PrivateKey) Zero() {
	// Overwrite private key material with zeros
	for i := range r.RSA3072PrivateKey {
		r.RSA3072PrivateKey[i] = 0
	}
	log.Debug("RSA-3072 private key securely erased")
}

// Helper method to convert byte array to rsa.PrivateKey
func (r RSA3072PrivateKey) toRSAPrivateKey() (*rsa.PrivateKey, error) {
	// Extract modulus (N) from first 384 bytes
	nBytes := r.RSA3072PrivateKey[:384]
	n := new(big.Int).SetBytes(nBytes)

	// Extract private exponent (D) from next 384 bytes
	dBytes := r.RSA3072PrivateKey[384:768]
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

	// Validate key size is 3072 bits
	if privKey.Size() != 384 {
		return nil, oops.Errorf("unexpected RSA key size: got %d, want 384", privKey.Size())
	}

	return privKey, nil
}

// Generate creates a new RSA-3072 private key
func (r *RSA3072PrivateKey) Generate() (types.SigningPrivateKey, error) {
	// Generate a new RSA-3072 private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, oops.Errorf("failed to generate RSA-3072 key: %w", err)
	}

	// I2P-compliant format: Store modulus (384 bytes) + private exponent (384 bytes)
	var newKey RSA3072PrivateKey

	// Store the modulus (N) - first 384 bytes
	modulusBytes := privateKey.N.Bytes()
	if len(modulusBytes) > 384 {
		return nil, oops.Errorf("RSA modulus exceeds expected size")
	}
	// Pad with leading zeros if needed
	copy(newKey.RSA3072PrivateKey[384-len(modulusBytes):384], modulusBytes)

	// Store the private exponent (D) - next 384 bytes
	dBytes := privateKey.D.Bytes()
	if len(dBytes) > 384 {
		return nil, oops.Errorf("RSA private exponent exceeds expected size")
	}
	// Pad with leading zeros if needed
	copy(newKey.RSA3072PrivateKey[768-len(dBytes):768], dBytes)

	log.Debug("RSA-3072 private key generated successfully")
	return &newKey, nil
}

var (
	_ types.PrivateKey = (*RSA3072PrivateKey)(nil)
	_ types.Signer     = RSA3072PrivateKey{}
)
