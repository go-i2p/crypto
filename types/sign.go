package types

import "github.com/samber/oops"

// Common error types for digital signature operations across the go-i2p/crypto library.
// These standardized errors provide consistent error handling for signature validation,
// key format validation, and signature size verification across all signature algorithms.
var (
	// ErrBadSignatureSize indicates that a signature has an invalid length for the algorithm.
	// This error is returned when signature bytes don't match the expected size for the signature scheme.
	ErrBadSignatureSize = oops.Errorf("bad signature size")

	// ErrInvalidKeyFormat indicates that a key has invalid format or structure.
	// This error is returned when key bytes cannot be parsed or don't conform to algorithm requirements.
	ErrInvalidKeyFormat = oops.Errorf("invalid key format")

	// ErrInvalidSignature indicates that signature verification failed.
	// This error is returned when a signature is mathematically invalid or doesn't match the data.
	ErrInvalidSignature = oops.Errorf("invalid signature")
)

// Verifier interface defines the contract for verifying digital signatures.
// All signature verification implementations must satisfy this interface to provide
// consistent signature validation across different cryptographic algorithms in the library.
type Verifier interface {
	// VerifyHash verifies a digital signature against a pre-computed hash.
	// This method accepts a hash digest and signature bytes, returning nil if the signature
	// is mathematically valid for the hash, or an error if verification fails.
	// This is the primary verification method for performance-critical applications.
	VerifyHash(h, sig []byte) error

	// Verify verifies a digital signature against raw data.
	// This convenience method hashes the data internally and calls VerifyHash.
	// It provides a simplified interface for applications that don't need to manage hashing separately.
	Verify(data, sig []byte) error
}

// SigningPublicKey interface defines the contract for public keys used in digital signatures.
// This interface provides methods for creating signature verifiers and accessing key metadata
// required for validating signatures created by the corresponding private key.
type SigningPublicKey interface {
	// NewVerifier creates a new Verifier instance using this public key.
	// The returned verifier can validate signatures created with the corresponding private key.
	// Returns an error if the public key format is invalid or verifier creation fails.
	NewVerifier() (Verifier, error)

	// Len returns the length of this public key in bytes.
	// This method provides the size of the key material for validation and serialization purposes.
	Len() int

	// Bytes returns the raw byte representation of this public key.
	// The returned bytes contain the complete public key material in the format
	// expected by the specific digital signature algorithm implementation.
	Bytes() []byte
}

// Signer interface defines the contract for creating digital signatures.
// All signature creation implementations must satisfy this interface to provide
// consistent signing operations across different cryptographic algorithms in the library.
type Signer interface {
	// Sign creates a digital signature for the provided data.
	// This convenience method hashes the data internally and calls SignHash.
	// It provides a simplified interface for applications that don't need to manage hashing separately.
	Sign(data []byte) (sig []byte, err error)

	// SignHash creates a digital signature for a pre-computed hash.
	// This method accepts a hash digest and returns the signature bytes.
	// This is the primary signing method for performance-critical applications and when
	// custom hashing algorithms or multiple signature operations are needed.
	SignHash(h []byte) (sig []byte, err error)
}

// SigningPrivateKey interface defines the contract for private keys used in digital signatures.
// This interface provides methods for creating signers, generating new keys, and managing
// the private key lifecycle including access to the corresponding public key.
type SigningPrivateKey interface {
	// NewSigner creates a new Signer instance using this private key.
	// The returned signer can create digital signatures that can be verified with the
	// corresponding public key. Returns an error if the private key format is invalid.
	NewSigner() (Signer, error)

	// Len returns the length of this private key in bytes.
	// This method provides the size of the key material for validation and serialization purposes.
	Len() int

	// Public extracts and returns the corresponding public signing key.
	// This method derives the public key from the private key material for signature verification.
	// Returns an error if the private key is invalid or public key derivation fails.
	Public() (SigningPublicKey, error)

	// Generate creates a new private key and stores it in this instance.
	// This method replaces the current key material with a newly generated private key.
	// Returns the updated private key instance or an error if key generation fails.
	Generate() (SigningPrivateKey, error)
}
