package types

// PublicKey interface defines the basic contract for all public key types.
// This interface provides fundamental methods for accessing key metadata and raw key material
// that are common across different cryptographic algorithms and key purposes.
type PublicKey interface {
	// Len returns the length of this public key in bytes.
	// This method provides the size of the key material for validation, serialization,
	// and buffer allocation purposes across different cryptographic implementations.
	Len() int

	// Bytes returns the raw byte representation of this public key.
	// The returned bytes contain the complete public key material in the format
	// expected by the specific cryptographic algorithm implementation.
	Bytes() []byte
}

// ReceivingPublicKey interface defines the contract for public keys used for receiving encrypted data.
// This interface extends the basic PublicKey interface with encryption capabilities, enabling
// the creation of encrypters for secure data transmission to the key holder.
type ReceivingPublicKey interface {
	// Len returns the length of this public key in bytes.
	// This method provides the size of the key material for validation and serialization purposes.
	Len() int

	// Bytes returns the raw byte representation of this public key.
	// The returned bytes contain the complete public key material formatted for the encryption algorithm.
	Bytes() []byte

	// NewEncrypter creates a new Encrypter instance using this public key.
	// The returned encrypter can encrypt data that can only be decrypted by the holder
	// of the corresponding private key. Returns an error if encrypter creation fails.
	NewEncrypter() (Encrypter, error)
}
