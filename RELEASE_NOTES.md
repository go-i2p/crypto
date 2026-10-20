Release notes for: `crypto` Version `0.1.70003`
==============================================

Spec-compliance audit: wire-format fixes and removal of non-spec APIs.

Behaviour changes (interop-critical):

- tunnel: fixed the AES tunnel layer cipher field layout. The IV is now written
  at bytes 4..19 and the payload CBC'd over bytes 20..1027 (the full 1008-byte
  region), with the 4-byte tunnel ID left cleartext at bytes 0..3, matching the
  Tunnel Message spec. Previously the IV landed at bytes 0..15 and the last 4
  payload bytes were emitted unencrypted. Added named offset constants and
  spec-layout tests.
- tunnel: removed the deprecated long-record format from the build-record entry
  points. EncryptBuildRequest/DecryptBuildRequest/EncryptOwnBuildReply/
  DecryptOwnBuildReply/ObfuscateOtherBuildRecord and the five size checks now
  accept only the short (0.9.51+) record sizes; the long format is "Deprecated,
  obsolete" per tunnel-creation-ecies.md and used a different reply nonce and AES
  obfuscation. The LongBuild*Size constants are retained as reference values.
- chacha20: the unauthenticated STREAM cipher now starts at block counter 1, as
  the I2P STREAM definition requires (encryptedleaseset.md §Definitions: "with
  the initial counter set to 1"). Verified against RFC 7539 §A.2 Test Vector #2.
- red25519: reimplemented the Red25519 scheme directly (no upstream wrapper). It
  now uses H(x)=SHA-512("I2P_Red25519H(x)"||x), the len_u16(M)||M length prefix
  with the 65534-byte cap, an 80-byte random nonce T (so every signature
  differs), mod-L key reduction without Ed25519 clamping, cofactor verification,
  and ADDITIVE blinding (A' = A + [alpha]B, a' = (a+alpha) mod L) that agrees
  with the ed25519 package. Passes all ten test vectors published in
  red25519.md §Test vectors.

Removed (non-spec / dead APIs):

- tunnel: TunnelEncryptionECIES (value 1), ECIESEncryptor/ECIESDecryptor, and
  NewTunnelCrypto. NewTunnelEncryptor now accepts only TunnelEncryptionAES.
- curve25519: Curve25519Signer/Curve25519Verifier and the NewSigner/NewVerifier
  methods. X25519 is key-agreement only; no I2P signature type uses it.
- red25519: NewKeyFromSeed and ComposeBlindingFactors (no spec concept); the
  SeedSize constant.
- elg: the dead PrivateKey wrapper struct; added ElgNilPublicKey so a nil key no
  longer misreports as ElgEncryptTooBig.

Ed25519 / Ed25519ph:

- added NewEd25519PrivateKeyFromSeed / NewEd25519phPrivateKeyFromSeed and Seed()
  accessors so the 32-byte SigningPrivateKey form a Java router uses
  (common-structures.md §SigningPrivateKey) can be imported/exported; the
  64-byte in-memory layout is documented as a Go detail.

Blinding:

- ed25519.BlindPublicKey and red25519.BlindPublicKey now reject small-order input
  points, enforcing encryptedleaseset.md §Goals ("blinded public keys must be on
  the Ed25519 curve and prime-order subgroup").

rand:

- cryptoSource no longer returns the constant 1 on CSPRNG failure; it panics and
  exposes Int63Err/Uint64Err so callers can handle a dead entropy source.
- SecureReader's entropy gate is now advisory (log-only); it no longer retries and
  fails genuine CSPRNG output. Deleted the unused EntropySampleSize constant.

Documentation: corrected the "standard for I2P tunnel encryption" claims in
chacha20/chacha20poly1305 (tunnel layer encryption is AES type 0 only), added the
"no I2P spec uses Argon2" disclaimer, named the ECIES §1f subsections, and added
elligator2/doc.go with its §2a/§2 citations.

Release notes for: `crypto` Version `0.1.70002`
==============================================

Spec-compliance audit fixes (ECIES-X25519-AEAD-Ratchet, Proposal 144).

Behaviour changes:

- ratchet: implemented the Noise Split() that section 4a makes mandatory.
  Session now keeps independent symmetric ratchets, tag ratchets, message
  counters and look-ahead windows for the inbound and outbound directions.
  Previously both directions shared one chain, which let a session's outbound
  and inbound streams collide. NewSessionFromECIESWithRole and the Role type
  expose the initiator/responder choice; NewSessionFromECIES is unchanged and
  remains the initiator-side wrapper. Note that sessions created before this
  release derive different keys than after it, and the per-direction split
  means two peers must be given opposite roles.
- ratchet: added Session.PerformReceivingDHRatchet (the inbound half of a
  NextKey exchange), Session.GenerateNewDHKeyPair, GetReceivingNextTag and
  GetReceivingMessageNumber. PerformDHRatchet now advances only the sending
  direction, as the spec's "a ratchet is for a single direction" requires.
- elligator2: added GenerateEncodedKeyPair, which returns the ENCODE_ELG2
  output alongside the key pair so the map is not computed twice per message
  (section 2a Notes). ecies now uses it.
- ecies: added spec-derived known-answer tests for the one-time key schedule
  (protocol name, each MixHash step, and the MixKey output) and ratchet added
  one for Split. These are computed from the specification text, not from this
  library, so they fail if the key schedule drifts.
- Makefile: `make test` and `make build` were broken (they inherited targets
  from the go-i2p monorepo that do not exist in this module). Replaced with
  library-appropriate build/test/vet/lint/cover targets.
- CI: the test matrix ran Go 1.22-1.24 while go.mod requires 1.26.8, so those
  jobs could never build. Aligned to 1.26.x.

Documentation corrections:

- tunnel: the ECIES option is NOT part of any I2P specification. No tunnel
  specification defines a ChaCha20/ECIES layer encryption type; I2P's AES
  layer encryption is the only defined scheme. Corrected the "follows Proposal
  144", "recommended default", "218-byte records (78% smaller)" and "default
  for new tunnel builds with 0.9.51+" claims across the package docs and
  README, and documented the measured record sizes.
- kdf: removed "AttachPayloadKDF" from the list of spec-mandated info strings -
  it appears in no I2P specification - and listed the strings that are real.
- aes: corrected the claim that struct literals and zero-value keys are
  "rejected". The constructors validate lengths only; an all-zero key of the
  correct length is accepted. Documented what is and is not enforced.
- ecies, ratchet, README: documented what is not implemented (New Session
  Reply, payload block format, Existing Session framing) and removed the
  unqualified "implements the spec exactly" marketing.
- types: documented the RFC 5869 vs I2P spec argument-order difference between
  KeyDeriver.Derive and kdf.StandardHKDF.

Release notes for: `crypto` Version `0.1.70001`
==============================================

Resolve parameter-order issues in HKDF, KDF, Argon2id

Release notes for: `crypto` Version `0.1.57`
==============================================

This release is largely unchanged from the last.

Release notes for: `crypto` Version `0.1.4`
==============================================

This release adds preliminary, untested support for Argon2ID as a KeyDeriver.
It is unused in the rest of the `go-i2p` codebase at this time and should not affect anything.
Other than that, the library is unchanged.

Release notes for: `crypto` Version `0.1.3`
==============================================

This release resolves a compilation issue introduced during late December due to a peculiar build environment.
This code was intended to analyze information in the NetDB for unusual patterns by identifying(in a granular way) keys which are invalid.
It is necessary to resolve other compilation issues in the go-i2p library stack.

Thanks to @Nick2k4L for pointing out the issue.
