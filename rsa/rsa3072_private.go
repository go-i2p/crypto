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

// RSA3072PrivateKey represents a 3072-bit RSA private key in I2P format.
// The key data is stored as a 768-byte array containing the modulus (384 bytes)
// and private exponent (384 bytes) following I2P cryptographic specifications.
// This type implements types.Signer and provides enhanced security over RSA-2048.
// RSA-3072 offers equivalent security to 128-bit symmetric encryption.
//
// ⚠️ CRITICAL SECURITY WARNING ⚠️
// Always use NewRSA3072PrivateKey() to create instances.
// Do NOT construct directly with &RSA3072PrivateKey{} or RSA3072PrivateKey{}.
type RSA3072PrivateKey struct {
	RSA3072PrivateKey [768]byte // I2P-compliant: 384 bytes modulus + 384 bytes private exponent
}

// NewRSA3072PrivateKey creates a validated RSA-3072 private key from bytes.
//
// The input data must be exactly 768 bytes in I2P format:
//   - First 384 bytes: modulus (N) in big-endian
//   - Next 384 bytes: private exponent (D) in big-endian
//
// Returns an error if:
//   - data length is not exactly 768 bytes
//   - data is all zeros (cryptographically invalid)
//
// The returned key is a defensive copy - modifications to the input
// slice will not affect the key.
func NewRSA3072PrivateKey(data []byte) (*RSA3072PrivateKey, error) {
	if len(data) != 768 {
		return nil, oops.Errorf("RSA-3072 private key must be 768 bytes, got %d: %w", len(data), ErrInvalidKeySize)
	}

	// Check for all-zero key (cryptographically invalid)
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, oops.Errorf("RSA-3072 private key cannot be all zeros: %w", ErrInvalidKeyFormat)
	}

	// Create defensive copy
	var key RSA3072PrivateKey
	copy(key.RSA3072PrivateKey[:], data)

	log.Debug("RSA-3072 private key created successfully")
	return &key, nil
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
	// Convert I2P byte array format to standard RSA private key structure
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		return nil, oops.Errorf("failed to parse RSA private key: %w", err)
	}

	// Extract public key components from the private key structure
	pubKey := privKey.Public().(*rsa.PublicKey)
	pubBytes := pubKey.N.Bytes()

	// Create and return the RSA3072PublicKey in I2P format
	var publicKey RSA3072PublicKey
	// Pad with zeros if necessary to maintain I2P 384-byte format (big-endian)
	if len(pubBytes) <= 384 {
		copy(publicKey[384-len(pubBytes):], pubBytes)
	} else {
		// Truncate if modulus is larger than expected (rare edge case for RSA-3072)
		copy(publicKey[:], pubBytes[len(pubBytes)-384:])
	}

	log.Debug("RSA-3072 public key derived successfully")
	return publicKey, nil
}

// Zero implements types.PrivateKey - securely erases key material
func (r *RSA3072PrivateKey) Zero() {
	// Overwrite private key material with zeros to prevent memory leakage
	// This is critical for security as RSA-3072 keys contain highly sensitive cryptographic material
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
	log.Debug("Generating new RSA-3072 private key")
	stdPrivKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.WithError(err).Error("Failed to generate RSA-3072 private key")
		return nil, oops.Errorf("failed to generate RSA-3072 key: %w", err)
	}

	// Convert to our format
	var newKey RSA3072PrivateKey

	// Extract modulus (384 bytes for RSA-3072)
	nBytes := stdPrivKey.N.Bytes()
	if len(nBytes) <= 384 {
		copy(newKey.RSA3072PrivateKey[384-len(nBytes):384], nBytes)
	} else {
		copy(newKey.RSA3072PrivateKey[:384], nBytes[len(nBytes)-384:])
	}

	// Extract private exponent (384 bytes for RSA-3072)
	dBytes := stdPrivKey.D.Bytes()
	if len(dBytes) <= 384 {
		copy(newKey.RSA3072PrivateKey[768-len(dBytes):], dBytes)
	} else {
		copy(newKey.RSA3072PrivateKey[384:], dBytes[len(dBytes)-384:])
	}

	log.Debug("New RSA-3072 private key generated successfully")
	return &newKey, nil
}

var (
	_ types.PrivateKey = (*RSA3072PrivateKey)(nil)
	_ types.Signer     = RSA3072PrivateKey{}
)
