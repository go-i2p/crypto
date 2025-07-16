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
// TunnelKey represents a symmetric key for encrypting tunnel messages (32 bytes).
// Moved from: tunnel.go
type TunnelKey [32]byte

// TunnelIV represents the initialization vector for tunnel message encryption operations.
// The IV provides randomization for CBC mode encryption and should be unique for each tunnel message
// to prevent cryptographic attacks. In I2P tunnel messages, the IV occupies the first 16 bytes
// of the TunnelData structure and serves as the randomization source for CBC encryption.
// IVs must be unpredictable but do not need to be secret, following standard cryptographic practices.
// TunnelIV represents the initialization vector for a tunnel message.
// Moved from: tunnel.go
type TunnelIV []byte
