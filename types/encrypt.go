package types

// Encrypter interface defines the contract for encrypting data using cryptographic algorithms.
// All symmetric and asymmetric encryption implementations must satisfy this interface to provide
// consistent encryption operations across the go-i2p/crypto library.
type Encrypter interface {
	// Encrypt encrypts the provided plaintext data and returns the ciphertext.
	// It accepts a byte slice containing plaintext data and returns the encrypted ciphertext
	// or an error if encryption fails due to invalid data, key, or other cryptographic issues.
	Encrypt(data []byte) (enc []byte, err error)
}

// PublicEncryptionKey interface defines the contract for public keys used in asymmetric encryption.
// This interface provides methods for creating encrypters and accessing key metadata required
// for encrypting data that can only be decrypted by the corresponding private key.
type PublicEncryptionKey interface {
	// NewEncrypter creates a new Encrypter instance using this public key.
	// The returned encrypter can encrypt data that can only be decrypted with the corresponding
	// private key. Returns an error if the public key format is invalid or encrypter creation fails.
	NewEncrypter() (Encrypter, error)

	// Len returns the length of this public key in bytes.
	// This method provides the size of the key material for validation and serialization purposes.
	Len() int

	// Bytes returns the raw byte representation of this public key.
	// The returned bytes contain the complete public key material in the format
	// expected by the specific cryptographic algorithm implementation.
	Bytes() []byte
}
