package dsa

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha1"
	"math/big"
)

// DSASigner provides DSA digital signature creation functionality.
// This type implements the types.Signer interface for generating DSA signatures
// using SHA-1 hash algorithm as specified by the I2P protocol. DSASigner wraps
// a standard crypto/dsa.PrivateKey and provides I2P-compatible signature formatting.
type DSASigner struct {
	k *dsa.PrivateKey
}

// Sign generates a DSA signature for the provided data using SHA-1 hashing.
// This method first computes the SHA-1 hash of the input data, then creates a DSA signature
// using the standard DSA algorithm (r, s) values. The signature is returned in I2P format
// as a 40-byte array containing r (20 bytes) followed by s (20 bytes).
// Returns the signature bytes or an error if signing fails due to invalid key or data.
func (ds *DSASigner) Sign(data []byte) (sig []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Signing data with DSA")
	// Hash data with SHA-1 as required by I2P DSA specification
	h := sha1.Sum(data)
	sig, err = ds.SignHash(h[:])
	return
}

// SignHash generates a DSA signature for a pre-computed hash digest.
// This method creates a DSA signature directly from a hash digest using the DSA algorithm.
// The hash should be 20 bytes (SHA-1) for optimal security and I2P compatibility.
// Returns a 40-byte signature in I2P format (r||s) or an error if signing fails.
// This is the primary signing method for performance-critical applications.
func (ds *DSASigner) SignHash(h []byte) (sig []byte, err error) {
	log.WithField("hash_length", len(h)).Debug("Signing hash with DSA")
	var r, s *big.Int
	// Generate DSA signature using cryptographically secure randomness
	r, s, err = dsa.Sign(rand.Reader, ds.k, h)
	if err == nil {
		// Format signature in I2P standard: r (20 bytes) || s (20 bytes)
		sig = make([]byte, 40)
		rb := r.Bytes()
		rl := len(rb)
		// Zero-pad r value to 20 bytes (big-endian format)
		copy(sig[20-rl:20], rb)
		sb := s.Bytes()
		sl := len(sb)
		// Zero-pad s value to 20 bytes (big-endian format)
		copy(sig[20+(20-sl):], sb)
		log.WithField("sig_length", len(sig)).Debug("DSA signature created successfully")
	} else {
		log.WithError(err).Error("Failed to create DSA signature")
	}
	return
}
