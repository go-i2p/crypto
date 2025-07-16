package tunnel

import "github.com/go-i2p/logger"

// log provides structured logging for tunnel cryptographic operations.
// This logger instance is configured for the go-i2p/crypto tunnel module and enables
// debugging of tunnel encryption/decryption processes, layer key operations, and error tracking.
// Logger instance for Tunnel package operations
// Moved from: tunnel.go
var log = logger.GetGoI2PLogger()
