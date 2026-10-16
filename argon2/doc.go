// Package argon2 provides key derivation using the Argon2id algorithm.
//
// Argon2id is a memory-hard key derivation function. "Memory-hard" means it
// needs a lot of RAM to compute, which makes it slow and expensive for
// attackers using specialized hardware (GPUs or ASICs) to guess passwords.
// It is the winner of the Password Hashing Competition and is a strong choice
// for turning a password or secret into a usable key.
//
// # How it works
//
//   - You give it input key material (a password or secret), a salt (random
//     bytes that make each result unique), and some context ("info").
//   - It returns a derived key of the length you request.
//
// # Usage
//
// Derivation is performed through an [Argon2id] instance (or the ready-made
// [Argon2idKDF] package variable), not package-level functions:
//
//   - Derive with custom parameters:
//
//     derivedKey, err := argon2.Argon2idKDF.Derive(ikm, salt, info, keyLen)
//
//   - Derive with the default costs:
//
//     derivedKey, err := argon2.Argon2idKDF.DeriveDefault(ikm)
//
// Note that Argon2id requires a non-empty salt, so DeriveDefault (which passes
// no salt) returns [ErrInvalidSalt]; call Derive with an explicit salt.
//
// This package wraps golang.org/x/crypto/argon2 for the underlying
// algorithm.
package argon2
