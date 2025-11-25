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

// RSA2048PrivateKey represents a 2048-bit RSA private key in I2P format.
// The key data is stored as a 512-byte array containing both the modulus (256 bytes)
// and private exponent (256 bytes) as specified by I2P cryptographic standards.
// This type implements types.Signer for creating digital signatures.
//
// ⚠️ CRITICAL SECURITY WARNING ⚠️
// Always use NewRSA2048PrivateKey() to create instances.
// Do NOT construct directly with &RSA2048PrivateKey{} or RSA2048PrivateKey{}.
//
// Example usage:
//
//	// WRONG - Creates invalid zero-value key
//	var key RSA2048PrivateKey
//
//	// CORRECT - Validates key data
//	key, err := NewRSA2048PrivateKey(keyBytes)
type RSA2048PrivateKey struct {
	RSA2048PrivateKey [512]byte // I2P-compliant: 256 bytes modulus + 256 bytes private exponent
}

// NewRSA2048PrivateKey creates a validated RSA-2048 private key from bytes.
//
// The input data must be exactly 512 bytes in I2P format:
//   - First 256 bytes: modulus (N) in big-endian
//   - Next 256 bytes: private exponent (D) in big-endian
//
// Returns an error if:
//   - data length is not exactly 512 bytes
//   - data is all zeros (cryptographically invalid)
//
// The returned key is a defensive copy - modifications to the input
// slice will not affect the key.
func NewRSA2048PrivateKey(data []byte) (*RSA2048PrivateKey, error) {
	if len(data) != 512 {
		return nil, oops.Errorf("RSA-2048 private key must be 512 bytes, got %d: %w", len(data), ErrInvalidKeySize)
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
		return nil, oops.Errorf("RSA-2048 private key cannot be all zeros: %w", ErrInvalidKeyFormat)
	}

	// Create defensive copy
	var key RSA2048PrivateKey
	copy(key.RSA2048PrivateKey[:], data)

	log.Debug("RSA-2048 private key created successfully")
	return &key, nil
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
	// Pad with zeros if necessary to maintain I2P 256-byte format (big-endian)
	// This ensures consistent key size regardless of leading zero bytes in the modulus
	if len(pubBytes) <= 256 {
		copy(publicKey[256-len(pubBytes):], pubBytes)
	} else {
		// Truncate if modulus is larger than expected (rare edge case)
		copy(publicKey[:], pubBytes[len(pubBytes)-256:])
	}

	log.Debug("RSA-2048 public key extracted successfully")
	return publicKey, nil
}

// Zero implements types.PrivateKey.
// Securely erases key material
func (r *RSA2048PrivateKey) Zero() {
	// Overwrite private key material with zeros to prevent memory leakage
	// This is critical for security as private keys contain sensitive cryptographic material
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

	// I2P-compliant format requires storing modulus (256 bytes) + private exponent (256 bytes)
	// This follows I2P's standard key representation for network compatibility
	var privKey RSA2048PrivateKey

	// Store the modulus (N) in the first 256 bytes with proper padding
	modulusBytes := stdPrivKey.N.Bytes()
	if len(modulusBytes) > 256 {
		return nil, ErrInvalidKeySize
	}
	// Pad with leading zeros to maintain exact 256-byte size requirement
	copy(privKey.RSA2048PrivateKey[256-len(modulusBytes):256], modulusBytes)

	// Store the private exponent (D) in the next 256 bytes with proper padding
	dBytes := stdPrivKey.D.Bytes()
	if len(dBytes) > 256 {
		return nil, ErrInvalidKeySize
	}
	// Pad with leading zeros to maintain exact 256-byte size requirement
	copy(privKey.RSA2048PrivateKey[512-len(dBytes):512], dBytes)

	log.Debug("New RSA2048 private key generated successfully")
	return privKey, nil
}

// Helper method to convert I2P format to rsa.PrivateKey
func (r RSA2048PrivateKey) toRSAPrivateKey() (*rsa.PrivateKey, error) {
	// Extract modulus (N) from first 256 bytes of I2P key format
	nBytes := r.RSA2048PrivateKey[:256]
	n := new(big.Int).SetBytes(nBytes)

	// Extract private exponent (D) from next 256 bytes of I2P key format
	dBytes := r.RSA2048PrivateKey[256:512]
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

	// Validate key size is exactly 2048 bits (256 bytes) as expected for RSA-2048
	if privKey.Size() != 256 {
		return nil, oops.Errorf("unexpected RSA key size: got %d, want 256", privKey.Size())
	}

	return privKey, nil
}

var (
	_ types.PrivateKey = (*RSA2048PrivateKey)(nil)
	_ types.Signer     = RSA2048PrivateKey{}
)
