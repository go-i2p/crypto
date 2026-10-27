package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/go-i2p/logger"
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
	log.WithFields(logger.Fields{"pkg": "tunnel", "func": "NewAESEncryptor"}).Debug("Creating new AES tunnel encryptor")

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
		log.WithFields(logger.Fields{"pkg": "tunnel", "func": "NewAESEncryptor"}).WithError(err).Error("Failed to create layer cipher")
		return nil, ErrCipherCreationFailed
	}

	// Initialize IV encryption cipher using AES-256
	// This cipher encrypts initialization vectors for enhanced security
	encryptor.ivKey, err = aes.NewCipher(ivKey[:])
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "tunnel", "func": "NewAESEncryptor"}).WithError(err).Error("Failed to create IV cipher")
		return nil, ErrCipherCreationFailed
	}

	log.WithFields(logger.Fields{"pkg": "tunnel", "func": "NewAESEncryptor"}).Debug("AES tunnel encryptor created successfully")
	return encryptor, nil
}

// Encrypt encrypts plaintext data using AES-256-CBC dual-layer encryption.
// For AES tunnel encryption, the input should be exactly 1008 bytes of payload
// data (a random 16-byte IV is then written at bytes 4..19); a full 1028-byte
// record is also accepted and used as-is.
//
// The record layout follows the Tunnel Message specification
// (https://i2p.net/en/docs/specs/tunnel-message/, "Tunnel Message
// (Encrypted)"): Tunnel ID bytes 0..3 (4 bytes, cleartext, nonzero), IV bytes
// 4..19 (16 bytes), Encrypted Data bytes 20..1027 (1008 bytes). Total size 1028
// bytes.
//
// When the 1008-byte payload-only form is used, bytes 0..3 are left zero: the
// tunnel ID is caller-supplied framing, not a cryptographic value, so set it
// before putting the record on the wire.
//
// Returns the complete tunnel data (1028 bytes) or error if encryption fails.
// This implements the TunnelEncryptor interface for AES-256-CBC encryption.
func (a *AESEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "tunnel", "func": "AESEncryptor.Encrypt"}).Debug("Encrypting data with AES-256-CBC tunnel encryption")

	// For AES, we expect either 1008 bytes (payload only) or 1028 bytes (full tunnel data)
	var td TunnelData

	if len(plaintext) == TunnelPayloadSize {
		// Payload only - generate the random IV into bytes 4..19 and copy the
		// payload into bytes 20..1027, per the spec's field offsets.
		if _, err := rand.Read(td[TunnelIVOffset : TunnelIVOffset+TunnelIVSize]); err != nil {
			log.WithFields(logger.Fields{"pkg": "tunnel", "func": "AESEncryptor.Encrypt"}).WithError(err).Error("Failed to generate IV for AES encryption")
			return nil, ErrEncryptionFailed
		}
		copy(td[TunnelPayloadOffset:], plaintext)
	} else if len(plaintext) == TunnelMessageSize {
		// Full tunnel data provided: bytes 0..3 are the caller's cleartext
		// tunnel ID and are carried through untouched.
		copy(td[:], plaintext)
	} else {
		log.WithFields(logger.Fields{"pkg": "tunnel", "func": "AESEncryptor.Encrypt", "length": len(plaintext)}).Error("Invalid plaintext length for AES tunnel encryption")
		return nil, ErrEncryptionFailed
	}

	// Perform in-place encryption on tunnel data
	if err := a.encryptTunnelData(&td); err != nil {
		return nil, err
	}

	// Return the encrypted tunnel data as byte slice
	result := make([]byte, TunnelMessageSize)
	copy(result, td[:])
	return result, nil
}

// processTunnelData performs the dual-layer AES tunnel processing common to both
// encryption and decryption, using the provided IV operation and CBC block mode
// constructor to determine the direction of processing.
func (a *AESEncryptor) processTunnelData(td *TunnelData, ivOp func(dst, src []byte), newBlockMode func(cipher.Block, []byte) cipher.BlockMode, msg string) error {
	// Field offsets per the Tunnel Message specification:
	//   bytes 0..3   Tunnel ID   (cleartext, never touched here)
	//   bytes 4..19  IV          (16 bytes)
	//   bytes 20..1027 Encrypted Data (1008 bytes)
	//
	// Step 1: AES-256-ECB single-block transform on the IV (bytes 4..19) using
	// ivKey. Tunnel-Creation / Tunnel-Implementation §Participant Processing:
	// "encrypts the received IV with AES256/ECB using their IV key to determine
	// the current IV".
	ivOp(td[TunnelIVOffset:TunnelIVOffset+TunnelIVSize], td[TunnelIVOffset:TunnelIVOffset+TunnelIVSize])
	// Step 2: CBC encrypt/decrypt the payload region (bytes 20..1027 = 1008
	// bytes) using layerKey with the transformed IV. The whole 1008-byte region
	// is processed; there is no unencrypted tail.
	layerBlock := newBlockMode(a.layerKey, td[TunnelIVOffset:TunnelIVOffset+TunnelIVSize])
	layerBlock.CryptBlocks(td[TunnelPayloadOffset:], td[TunnelPayloadOffset:])
	// Step 3: AES-256-ECB single-block transform on the IV again (post-payload),
	// producing nextIV for forwarding. "encrypts the current IV with AES256/ECB
	// using their IV key again" - the double encryption of the IV (both before
	// and after use) helps address a class of confirmation attacks.
	ivOp(td[TunnelIVOffset:TunnelIVOffset+TunnelIVSize], td[TunnelIVOffset:TunnelIVOffset+TunnelIVSize])
	log.WithFields(logger.Fields{"pkg": "tunnel", "func": "AESEncryptor.processTunnelData"}).Debug(msg)
	return nil
}

// encryptTunnelData performs the actual in-place AES encryption on tunnel data.
// This is the internal method that implements the dual-layer encryption process.
func (a *AESEncryptor) encryptTunnelData(td *TunnelData) error {
	return a.processTunnelData(td, a.ivKey.Encrypt, cipher.NewCBCEncrypter, "AES tunnel data encrypted successfully")
}

// Decrypt removes one tunnel encryption layer using AES-256-CBC dual-layer
// decryption. The input must be exactly 1028 bytes of tunnel data.
//
// It returns the complete 1028-byte decrypted record, not just the 1008-byte
// payload region. This is what the I2P specifications require a forwarding hop
// to be able to produce: per Tunnel-Implementation §Participant Processing, a
// hop "encrypts the current IV with AES256/ECB using their IV key again" so
// that the IV it hands on is part of the message the next hop receives, and
// per Tunnel-Message ("Tunnel Message (Decrypted)") the decrypted view keeps
// the 4-byte Tunnel ID at bytes 0..3 and the 16-byte IV at bytes 4..19 ahead of
// the 1008-byte payload. Those two fields are exactly the framing a transit
// hop must forward, so discarding them makes transit forwarding impossible.
//
// The transform applied here is the exact inverse of [AESEncryptor.Encrypt]:
// AES-256/ECB-decrypt the received IV to recover the current IV, CBC-decrypt
// bytes 20..1027 with the layer key using that IV, then AES-256/ECB-decrypt the
// current IV once more to produce the IV forwarded to the next hop. Because the
// pair is symmetric, a record that has travelled through every hop's layer
// arrives back at the gateway's original IV, which the endpoint needs in order
// to verify the checksum (Tunnel-Message: the checksum is taken over the
// delivery instructions and fragments concatenated with the IV).
//
// Returns the 1028-byte decrypted record, or error if decryption fails.
// This implements the TunnelEncryptor interface for AES-256-CBC decryption.
func (a *AESEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "tunnel", "func": "AESEncryptor.Decrypt"}).Debug("Decrypting data with AES-256-CBC tunnel decryption")

	// AES tunnel decryption expects exactly 1028 bytes
	if len(ciphertext) != TunnelMessageSize {
		log.WithFields(logger.Fields{"pkg": "tunnel", "func": "AESEncryptor.Decrypt", "length": len(ciphertext)}).Error("Invalid ciphertext length for AES tunnel decryption")
		return nil, ErrDecryptionFailed
	}

	// Copy ciphertext to tunnel data structure
	var td TunnelData
	copy(td[:], ciphertext)

	// Perform in-place decryption on tunnel data
	if err := a.decryptTunnelData(&td); err != nil {
		return nil, err
	}

	// Return the whole decrypted record. Bytes 0..3 are the cleartext tunnel ID
	// framing supplied by the sender (never touched by the layer transform);
	// bytes 4..19 are the IV transformed for the next hop; bytes 20..1027 are
	// the inner layer's data region.
	result := make([]byte, TunnelMessageSize)
	copy(result, td[:])
	return result, nil
}

// decryptTunnelData performs the actual in-place AES decryption on tunnel data.
// This is the internal method that implements the dual-layer decryption process.
func (a *AESEncryptor) decryptTunnelData(td *TunnelData) error {
	return a.processTunnelData(td, a.ivKey.Decrypt, cipher.NewCBCDecrypter, "AES tunnel data decrypted successfully")
}

// Type returns the encryption scheme used by this encryptor (AES-256-CBC).
// This implements the TunnelEncryptor interface Type() method.
func (a *AESEncryptor) Type() TunnelEncryptionType {
	return TunnelEncryptionAES
}
