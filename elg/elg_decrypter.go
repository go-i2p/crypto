package elg

import "github.com/go-i2p/elgamal"

// elgDecrypter implements the types.Decrypter interface for ElGamal decryption.
// It wraps an ElGamal private key and provides secure decryption operations.
// This structure maintains the ElGamal private key parameters (P, G, X, Y) internally
// and implements constant-time decryption to prevent timing attacks during the process.
type elgDecrypter struct {
	// k stores the complete ElGamal private key with all domain parameters
	// including the prime modulus P, generator G, private exponent X, and public key Y
	k *elgamal.PrivateKey
}

// Decrypt decrypts ElGamal encrypted data using the stored private key.
// Applies I2P's ElGamal decryption format with zero padding enabled.
// Returns decrypted data or error if decryption fails or data is corrupted.
// The decryption process validates message integrity using SHA-256 checksums
// and implements constant-time operations to prevent side-channel attacks.
func (elg *elgDecrypter) Decrypt(data []byte) (dec []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Decrypting ElGamal data")
	// Use zero padding format for I2P compatibility with standard message structure
	// The zero padding parameter affects how the encrypted data components are parsed
	// TODO(psi): Verify if zero padding should be configurable for different I2P message types
	dec, err = elgamalDecrypt(elg.k, data, true) // TODO(psi): should this be true or false?
	if err != nil {
		log.WithError(err).Error("Failed to decrypt ElGamal data")
	} else {
		log.WithField("decrypted_length", len(dec)).Debug("ElGamal data decrypted successfully")
	}
	return
}
