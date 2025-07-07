package tunnel

// TunnelData represents the data structure for tunnel messages (1028 bytes).
// Moved from: tunnel.go
type TunnelData [1028]byte

// TunnelKey represents a symmetric key for encrypting tunnel messages (32 bytes).
// Moved from: tunnel.go
type TunnelKey [32]byte

// TunnelIV represents the initialization vector for a tunnel message.
// Moved from: tunnel.go
type TunnelIV []byte
