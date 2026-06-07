package kdf

// DEPRECATED: This file previously contained hardcoded test vectors for
// "SessionReplyTags" and "AttachPayloadKDF" that were based on incorrect
// reference implementations.
//
// REPLACED BY: i2p_vectors_test.go
//
// The test infrastructure has been migrated to use official test vectors from
// the i2p-vectors project located at /go-i2p/i2p-vectors/samples/crypto.json
//
// The new test infrastructure (TestI2PVectorsFromJSON) dynamically loads test
// vectors from the official i2p-vectors JSON files, ensuring compliance with
// the authoritative Java I2P reference implementation (version 2.12.0).
//
// To regenerate or update test vectors:
// 1. Update vectors in /go-i2p/i2p-vectors/samples/crypto.json
// 2. The test will automatically load and validate the new vectors
//
// See i2p_vectors_test.go for implementation details.
