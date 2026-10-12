// Package hmac provides HMAC (Hash-based Message Authentication Code) for
// I2P.
//
// HMAC is a way to prove that a message came from someone who knows a shared
// secret, and that the message has not been altered. It combines a hash
// function (such as SHA-256) with a secret key.
//
// This package is a thin wrapper around the standard library crypto/hmac,
// provided so that all go-i2p code imports HMAC from a single, auditable
// location.
//
// # Usage
//
//	mac := hmac.New(sha256.New, key)
//	mac.Write(data)
//	digest := mac.Sum(nil)
//
// Use hmac.Equal to compare two digests. It compares in constant time, which
// prevents timing attacks that could otherwise let an attacker forge a valid
// MAC.
//
// See RFC 2104 for the HMAC specification:
// https://datatracker.ietf.org/doc/html/rfc2104
package hmac
