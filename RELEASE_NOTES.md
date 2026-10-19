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
