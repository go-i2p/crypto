package tunnel

// TunnelData represents the standardized data structure for I2P tunnel messages (1028 bytes total).
// The structure follows I2P's tunnel message format where the first 16 bytes serve as the initialization
// vector (IV) and the remaining 1008 bytes contain the encrypted payload data. This fixed-size format
// ensures network compatibility and provides consistent message boundaries for tunnel encryption operations.
// The 1028-byte size aligns with I2P's network protocol requirements for efficient data transmission.
// TunnelData represents the data structure for tunnel messages (1028 bytes).
// Moved from: tunnel.go
type TunnelData [1028]byte

// TunnelKey represents a symmetric AES-256 key for encrypting tunnel messages (32 bytes).
// Each tunnel operation requires two separate TunnelKey instances: one for layer encryption
// and another for IV encryption. The 32-byte length provides 256-bit security strength
// compatible with AES-256 encryption used in I2P tunnel cryptography. These keys should be
// cryptographically random and generated using secure random number generators.
//
// ⚠️ CRITICAL SECURITY WARNING ⚠️
// Always use NewTunnelKey() to create instances.
// Do NOT construct directly with &TunnelKey{} or TunnelKey{}.
//
// Example usage:
//
//	// WRONG - Creates invalid zero-value key
//	var key TunnelKey
//
//	// CORRECT - Validates key data
//	key, err := NewTunnelKey(keyBytes)
type TunnelKey [32]byte

// NewTunnelKey creates a validated tunnel key from bytes.
//
// The input data must be exactly 32 bytes for AES-256 compatibility.
// Additionally, the key cannot be all zeros as this would provide
// no cryptographic security (weak/invalid key).
//
// Returns an error if:
//   - data length is not exactly 32 bytes
//   - data is all zeros (cryptographically invalid)
//
// The returned key is a defensive copy - modifications to the input
// slice will not affect the key.
func NewTunnelKey(data []byte) (*TunnelKey, error) {
	if len(data) != 32 {
		return nil, ErrInvalidKeySize
	}

	// Check for all-zero key (cryptographically invalid)
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		log.Error("Attempted to create all-zero tunnel key")
		return nil, ErrInvalidKey
	}

	// Create defensive copy
	var key TunnelKey
	copy(key[:], data)

	log.Debug("Tunnel key created successfully")
	return &key, nil
}

// TunnelIV represents the initialization vector for tunnel message encryption operations.
// The IV provides randomization for CBC mode encryption and should be unique for each tunnel message
// to prevent cryptographic attacks. In I2P tunnel messages, the IV occupies the first 16 bytes
// of the TunnelData structure and serves as the randomization source for CBC encryption.
// IVs must be unpredictable but do not need to be secret, following standard cryptographic practices.
// TunnelIV represents the initialization vector for a tunnel message.
// Moved from: tunnel.go
type TunnelIV []byte
