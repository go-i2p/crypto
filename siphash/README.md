# siphash

Wrapper around `github.com/dchest/siphash` providing SipHash-2-4 for the `go-i2p/crypto` ecosystem.

SipHash is used by NTCP2 for obfuscated frame-length encoding.

## Functions

| Function | Description |
|----------|-------------|
| `Hash(k0, k1, data)` | SipHash-2-4 → 64-bit digest |
| `Hash128(k0, k1, data)` | SipHash-2-4-128 → two 64-bit halves |
| `New(key)` | Streaming `hash.Hash64` for incremental hashing |
| `New128(key)` | Streaming `hash.Hash` for 128-bit SipHash |
