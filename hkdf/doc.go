// Package hkdf provides key derivation using the HKDF (HMAC-based Key
// Derivation Function) algorithm.
//
// HKDF turns a shared secret (input key material) into one or more strong
// keys. It is the standard way to stretch a short shared secret into
// encryption keys of the exact length you need. HKDF is defined in RFC 5869
// and is used throughout I2P, including the ECIES-X25519-AEAD-Ratchet
// scheme.
//
// # How it works
//
// HKDF follows RFC 5869 and has two steps:
//
//  1. Extract: distill the input key material into a pseudorandom key.
//  2. Expand: stretch that key to the desired length.
//
// Both steps take an "info" context string that binds the derived key to a
// specific purpose, so keys for different jobs never collide.
//
// See RFC 5869 for the HKDF specification:
// https://datatracker.ietf.org/doc/html/rfc5869
package hkdf
