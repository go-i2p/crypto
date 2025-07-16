package elg

import "golang.org/x/crypto/openpgp/elgamal"

// elgDecrypter implements the types.Decrypter interface for ElGamal decryption.
// It wraps an ElGamal private key and provides secure decryption operations.
type elgDecrypter struct {
	k *elgamal.PrivateKey
}

// Decrypt decrypts ElGamal encrypted data using the stored private key.
// Applies I2P's ElGamal decryption format with zero padding enabled.
// Returns decrypted data or error if decryption fails or data is corrupted.
func (elg *elgDecrypter) Decrypt(data []byte) (dec []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Decrypting ElGamal data")
	// Use zero padding format for I2P compatibility
	// TODO(psi): Verify if zero padding should be configurable for different I2P message types
	dec, err = elgamalDecrypt(elg.k, data, true) // TODO(psi): should this be true or false?
	if err != nil {
		log.WithError(err).Error("Failed to decrypt ElGamal data")
	} else {
		log.WithField("decrypted_length", len(dec)).Debug("ElGamal data decrypted successfully")
	}
	return
}
