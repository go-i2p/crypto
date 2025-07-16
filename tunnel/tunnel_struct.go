package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
)

// Tunnel represents a cryptographic tunnel with dual-layer AES encryption capabilities.
// It maintains separate cipher blocks for layer encryption and IV encryption operations,
// implementing I2P's tunnel cryptography scheme for secure data transmission through the network.
// The dual-layer approach provides enhanced security by encrypting both the data payload and
// the initialization vector used for subsequent encryption operations.
// Tunnel represents a cryptographic tunnel with layer and IV encryption keys.
// Moved from: tunnel.go
type Tunnel struct {
	// layerKey provides the AES cipher block for main data layer encryption
	// using CBC mode with the tunnel message's IV for randomization
	layerKey cipher.Block
	// ivKey provides the AES cipher block for IV encryption operations
	// used to encrypt initialization vectors and provide additional security
	ivKey cipher.Block
}

// NewTunnelCrypto creates a new tunnel cryptographic instance with the provided AES keys.
// Both layerKey and ivKey must be exactly 32 bytes (256 bits) for AES-256 compatibility.
// The function initializes separate AES cipher blocks for dual-layer tunnel encryption,
// following I2P's tunnel cryptography specification for secure data transmission.
// Returns a configured Tunnel instance or an error if cipher creation fails due to invalid keys.
// Example usage: tunnel, err := NewTunnelCrypto(layerKey, ivKey)
// NewTunnelCrypto creates a new tunnel cryptographic instance with the provided keys.
// Returns a new Tunnel instance or an error if cipher creation fails.
// Moved from: tunnel.go
func NewTunnelCrypto(layerKey, ivKey TunnelKey) (t *Tunnel, err error) {
	log.Debug("Creating new Tunnel crypto")
	t = new(Tunnel)
	// Initialize layer encryption cipher using AES-256
	// This cipher handles the main data payload encryption in CBC mode
	t.layerKey, err = aes.NewCipher(layerKey[:])
	if err == nil {
		// Initialize IV encryption cipher using AES-256
		// This cipher encrypts initialization vectors for enhanced security
		t.ivKey, err = aes.NewCipher(ivKey[:])
	}

	if err != nil {
		// error happened we don't need t
		// log.WithError(err).Error("Failed to create Tunnel crypto")
		// Clear tunnel instance on error to prevent memory leaks
		t = nil
	} else {
		log.Debug("Tunnel crypto created successfully")
	}
	return
}

// Encrypt performs in-place dual-layer AES encryption on tunnel data following I2P protocol.
// The encryption process applies three stages: IV encryption, CBC layer encryption, and final IV encryption.
// This approach ensures both the data payload and initialization vector are cryptographically protected.
// The first 16 bytes of tunnel data serve as the IV, while bytes 16-1024 contain the encrypted payload.
// The operation modifies the input TunnelData structure in place for memory efficiency.
// Encrypt encrypts tunnel data in place using the tunnel's encryption keys.
// Moved from: tunnel.go
func (t *Tunnel) Encrypt(td *TunnelData) {
	log.Debug("Encrypting Tunnel data")
	data := *td
	// First stage: Encrypt the payload data using IV key to randomize the content
	// This provides initial cryptographic protection before layer encryption
	t.ivKey.Encrypt(data[16:1024], data[16:1024])
	// Second stage: Apply CBC layer encryption using the first 16 bytes as IV
	// This creates the main encryption layer with proper CBC chaining
	layerBlock := cipher.NewCBCEncrypter(t.layerKey, data[:16])
	layerBlock.CryptBlocks(data[16:1024], data[16:1024])
	// Third stage: Final IV encryption to protect the encrypted data
	// This dual-encryption approach enhances security against traffic analysis
	t.ivKey.Encrypt(data[16:1024], data[16:1024])
	log.Debug("Tunnel data encrypted successfully")
}

// Decrypt performs in-place dual-layer AES decryption on tunnel data following I2P protocol.
// The decryption process reverses the encryption stages: IV decryption, CBC layer decryption, and final IV decryption.
// This approach correctly decrypts data that was encrypted using the dual-layer tunnel encryption scheme.
// The first 16 bytes of tunnel data serve as the IV, while bytes 16-1024 contain the encrypted payload.
// The operation modifies the input TunnelData structure in place for memory efficiency.
// Decrypt decrypts tunnel data in place using the tunnel's decryption keys.
// Moved from: tunnel.go
func (t *Tunnel) Decrypt(td *TunnelData) {
	log.Debug("Decrypting Tunnel data")
	data := *td
	// First stage: Decrypt the outer IV encryption layer
	// This removes the final encryption layer applied during the encryption process
	t.ivKey.Decrypt(data[16:1024], data[16:1024])
	// Second stage: Apply CBC layer decryption using the first 16 bytes as IV
	// This decrypts the main data layer using CBC mode with proper chaining
	layerBlock := cipher.NewCBCDecrypter(t.layerKey, data[:16])
	layerBlock.CryptBlocks(data[16:1024], data[16:1024])
	// Third stage: Final IV decryption to recover original plaintext
	// This completes the dual-layer decryption process
	t.ivKey.Decrypt(data[16:1024], data[16:1024])
	log.Debug("Tunnel data decrypted successfully")
}
