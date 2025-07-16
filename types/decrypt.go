package types

// Decrypter interface defines the contract for decrypting data using cryptographic algorithms.
// All symmetric and asymmetric decryption implementations must satisfy this interface to provide
// consistent decryption operations across the go-i2p/crypto library.
type Decrypter interface {
	// Decrypt decrypts the provided ciphertext data and returns the plaintext.
	// It accepts a byte slice containing encrypted data and returns the decrypted plaintext
	// or an error if decryption fails due to invalid data, key, or other cryptographic issues.
	Decrypt(data []byte) ([]byte, error)
}

// PrivateEncryptionKey interface defines the contract for private keys used in asymmetric encryption.
// This interface provides methods for creating decrypters, accessing the corresponding public key,
// and managing the private key lifecycle including secure memory cleanup.
type PrivateEncryptionKey interface {
	// NewDecrypter creates a new Decrypter instance using this private key.
	// The returned decrypter can decrypt data that was encrypted with the corresponding public key.
	// Returns an error if the private key format is invalid or decrypter creation fails.
	NewDecrypter() (Decrypter, error)

	// Public extracts and returns the corresponding public encryption key.
	// This method derives the public key from the private key material without exposing
	// sensitive private key data. Returns an error if key derivation fails.
	Public() (PublicEncryptionKey, error)

	// Bytes returns the raw byte representation of this private key.
	// The returned bytes contain the complete private key material in the format
	// expected by the specific cryptographic algorithm implementation.
	Bytes() []byte

	// Zero securely clears all sensitive private key data from memory.
	// This method should be called when the private key is no longer needed to prevent
	// memory disclosure attacks. After calling Zero, the key becomes unusable.
	Zero()
}
