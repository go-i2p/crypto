package types

// PrivateKey interface defines the contract for private keys used in digital signatures.
// This interface provides methods for accessing the corresponding public key, retrieving
// the raw key material, and securely clearing sensitive data from memory when no longer needed.
type PrivateKey interface {
	// Public returns the public key corresponding to this private key.
	// This method derives the public key from the private key material for signature verification.
	// Returns an error if the private key is invalid or public key derivation fails.
	Public() (SigningPublicKey, error)

	// Bytes returns the raw byte representation of this private key.
	// The returned bytes contain the complete private key material in the format
	// expected by the specific digital signature algorithm implementation.
	Bytes() []byte

	// Zero securely clears all sensitive private key data from memory.
	// This method overwrites the private key material to prevent memory disclosure attacks.
	// After calling Zero, the private key becomes unusable and should be discarded.
	Zero()
}
