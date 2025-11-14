package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// AESEncryptor implements tunnel encryption using dual-layer AES-256-CBC scheme.
// It maintains separate cipher blocks for layer encryption and IV encryption operations,
// implementing I2P's legacy tunnel cryptography for secure data transmission through the network.
// The dual-layer approach provides enhanced security by encrypting both the data payload and
// the initialization vector used for subsequent encryption operations.
// This implements the TunnelEncryptor interface for AES-256-CBC encryption (type 0).
type AESEncryptor struct {
	// layerKey provides the AES cipher block for main data layer encryption
	// using CBC mode with the tunnel message's IV for randomization
	layerKey cipher.Block
	// ivKey provides the AES cipher block for IV encryption operations
	// used to encrypt initialization vectors and provide additional security
	ivKey cipher.Block
}

// NewAESEncryptor creates a new AES-256-CBC tunnel encryptor with the provided keys.
// Both layerKey and ivKey must be exactly 32 bytes (256 bits) for AES-256 compatibility.
// The function initializes separate AES cipher blocks for dual-layer tunnel encryption,
// following I2P's tunnel cryptography specification for secure data transmission.
// Returns a configured AESEncryptor instance or an error if cipher creation fails due to invalid keys.
// Example usage: encryptor, err := NewAESEncryptor(layerKey, ivKey)
func NewAESEncryptor(layerKey, ivKey TunnelKey) (*AESEncryptor, error) {
	log.Debug("Creating new AES tunnel encryptor")

	// Validate key sizes before cipher creation
	if len(layerKey) != 32 {
		return nil, ErrInvalidKeySize
	}
	if len(ivKey) != 32 {
		return nil, ErrInvalidKeySize
	}

	encryptor := &AESEncryptor{}

	// Initialize layer encryption cipher using AES-256
	// This cipher handles the main data payload encryption in CBC mode
	var err error
	encryptor.layerKey, err = aes.NewCipher(layerKey[:])
	if err != nil {
		log.WithError(err).Error("Failed to create layer cipher")
		return nil, ErrCipherCreationFailed
	}

	// Initialize IV encryption cipher using AES-256
	// This cipher encrypts initialization vectors for enhanced security
	encryptor.ivKey, err = aes.NewCipher(ivKey[:])
	if err != nil {
		log.WithError(err).Error("Failed to create IV cipher")
		return nil, ErrCipherCreationFailed
	}

	log.Debug("AES tunnel encryptor created successfully")
	return encryptor, nil
}

// NewTunnelCrypto is deprecated. Use NewAESEncryptor instead.
// This function is kept for backward compatibility and will be removed in a future version.
func NewTunnelCrypto(layerKey, ivKey TunnelKey) (*AESEncryptor, error) {
	log.Warn("NewTunnelCrypto is deprecated, use NewAESEncryptor instead")
	return NewAESEncryptor(layerKey, ivKey)
}

// Encrypt encrypts plaintext data using AES-256-CBC dual-layer encryption.
// For AES tunnel encryption, the input should be exactly 1008 bytes of payload data.
// The method creates a 1028-byte tunnel structure with a 16-byte IV prefix.
// Returns the complete tunnel data (1028 bytes) or error if encryption fails.
// This implements the TunnelEncryptor interface for AES-256-CBC encryption.
func (a *AESEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	log.Debug("Encrypting data with AES-256-CBC tunnel encryption")

	// For AES, we expect either 1008 bytes (payload only) or 1028 bytes (full tunnel data)
	var td TunnelData

	if len(plaintext) == 1008 {
		// Payload only - generate random IV and copy payload
		if _, err := rand.Read(td[:16]); err != nil {
			log.WithError(err).Error("Failed to generate IV for AES encryption")
			return nil, ErrEncryptionFailed
		}
		copy(td[16:], plaintext)
	} else if len(plaintext) == 1028 {
		// Full tunnel data provided
		copy(td[:], plaintext)
	} else {
		log.WithField("length", len(plaintext)).Error("Invalid plaintext length for AES tunnel encryption")
		return nil, ErrEncryptionFailed
	}

	// Perform in-place encryption on tunnel data
	if err := a.encryptTunnelData(&td); err != nil {
		return nil, err
	}

	// Return the encrypted tunnel data as byte slice
	result := make([]byte, 1028)
	copy(result, td[:])
	return result, nil
}

// encryptTunnelData performs the actual in-place AES encryption on tunnel data.
// This is the internal method that implements the dual-layer encryption process.
func (a *AESEncryptor) encryptTunnelData(td *TunnelData) error {
	data := *td

	// First stage: Encrypt the payload data using IV key to randomize the content
	// This provides initial cryptographic protection before layer encryption
	a.ivKey.Encrypt(data[16:1024], data[16:1024])

	// Second stage: Apply CBC layer encryption using the first 16 bytes as IV
	// This creates the main encryption layer with proper CBC chaining
	layerBlock := cipher.NewCBCEncrypter(a.layerKey, data[:16])
	layerBlock.CryptBlocks(data[16:1024], data[16:1024])

	// Third stage: Final IV encryption to protect the encrypted data
	// This dual-encryption approach enhances security against traffic analysis
	a.ivKey.Encrypt(data[16:1024], data[16:1024])

	log.Debug("AES tunnel data encrypted successfully")
	return nil
}

// Decrypt decrypts ciphertext data using AES-256-CBC dual-layer decryption.
// For AES tunnel decryption, the input should be exactly 1028 bytes of tunnel data.
// Returns the 1008-byte payload (excluding 16-byte IV) or error if decryption fails.
// This implements the TunnelEncryptor interface for AES-256-CBC decryption.
func (a *AESEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	log.Debug("Decrypting data with AES-256-CBC tunnel decryption")

	// AES tunnel decryption expects exactly 1028 bytes
	if len(ciphertext) != 1028 {
		log.WithField("length", len(ciphertext)).Error("Invalid ciphertext length for AES tunnel decryption")
		return nil, ErrDecryptionFailed
	}

	// Copy ciphertext to tunnel data structure
	var td TunnelData
	copy(td[:], ciphertext)

	// Perform in-place decryption on tunnel data
	if err := a.decryptTunnelData(&td); err != nil {
		return nil, err
	}

	// Return the decrypted payload (excluding IV)
	result := make([]byte, 1008)
	copy(result, td[16:1024])
	return result, nil
}

// decryptTunnelData performs the actual in-place AES decryption on tunnel data.
// This is the internal method that implements the dual-layer decryption process.
func (a *AESEncryptor) decryptTunnelData(td *TunnelData) error {
	data := *td

	// First stage: Decrypt the outer IV encryption layer
	// This removes the final encryption layer applied during the encryption process
	a.ivKey.Decrypt(data[16:1024], data[16:1024])

	// Second stage: Apply CBC layer decryption using the first 16 bytes as IV
	// This decrypts the main data layer using CBC mode with proper chaining
	layerBlock := cipher.NewCBCDecrypter(a.layerKey, data[:16])
	layerBlock.CryptBlocks(data[16:1024], data[16:1024])

	// Third stage: Final IV decryption to recover original plaintext
	// This completes the dual-layer decryption process
	a.ivKey.Decrypt(data[16:1024], data[16:1024])

	log.Debug("AES tunnel data decrypted successfully")
	return nil
}

// Type returns the encryption scheme used by this encryptor (AES-256-CBC).
// This implements the TunnelEncryptor interface Type() method.
func (a *AESEncryptor) Type() TunnelEncryptionType {
	return TunnelEncryptionAES
}
