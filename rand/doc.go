// Package rand provides cryptographically secure random number generation
// for I2P.
//
// This package offers an API similar to the standard library math/rand, but
// every value it produces comes from crypto/rand, the operating system's
// secure random source. This makes it safe for generating keys, nonces, and
// other secrets.
//
// # How it differs from math/rand
//
//   - math/rand is fast but predictable. An attacker who sees a few outputs
//     can guess the rest.
//
//   - This package is slower but unpredictable. Use it for anything
//     security-sensitive.
//
//   - Seeding is a no-op here. Secure randomness does not use a seed.
package rand
