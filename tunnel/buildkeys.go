package tunnel

import (
	"crypto/sha256"

	"github.com/go-i2p/crypto/chacha20"
	"github.com/go-i2p/crypto/kdf"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Tunnel-Creation-ECIES build-record key derivation.
//
// Spec: https://i2p.net/en/docs/specs/tunnel-creation-ecies/ (updated 2025-06,
// accurate for 0.9.66). This is the mechanism the network actually uses to build
// tunnels: per the Low-level Cryptography spec, "X25519 tunnel creation has
// replaced ElGamal tunnel creation", and the short-record form below has been
// implemented since release 0.9.51 (the 528-byte long-record form of 0.9.48 is
// deprecated).
//
// Scope note: this file implements the *cryptographic primitives* only - the
// Noise_N key schedule, the AEAD over an already-serialized record, and the
// reply/layer key KDF chain. The record byte layouts themselves (the tunnel ID /
// next-router-hash / flags / request-time fields, the build-options Mapping,
// padding, record randomization, "fake" records, and the VariableTunnelBuild
// message assembly) are common data structures and protocol, and belong in
// ../common and ../go-noise, not here. Callers pass in the serialized plaintext
// record and get back the wire ciphertext.
//
// Two sizes are defined by the spec:
//
//	short (current): 154-byte request plaintext -> 218-byte ciphertext
//	                 202-byte reply  plaintext -> 218-byte ciphertext
//	long (deprecated): 464-byte request plaintext -> 528-byte ciphertext
//	                   512-byte reply  plaintext -> 528-byte ciphertext
//
// The ciphertext is [hop's truncated identity hash 16][sender ephemeral pubkey
// 32][ChaCha20-Poly1305 ciphertext][Poly1305 tag 16] for a *request*; the 16-byte
// hash prefix and 32-byte ephemeral key are framing that the caller writes, so
// these functions produce/consume only the encrypted region plus the tag.

const (
	// ShortBuildRequestSize is the unencrypted short BuildRequestRecord length
	// (spec: "Unencrypted size: 154 bytes").
	ShortBuildRequestSize = 154
	// ShortBuildReplySize is the unencrypted short BuildReplyRecord length
	// (spec: "Unencrypted size: 202 bytes").
	ShortBuildReplySize = 202
	// ShortBuildRecordSize is the complete on-wire short record, identical for
	// request and reply (spec: "Encrypted request and reply records will be 218
	// bytes"). A request is 16+32+154+16; a reply is 202+16.
	ShortBuildRecordSize = 218

	// ShortBuildRequestEncryptedSize is the AEAD output for a short request
	// record: the 154-byte plaintext plus the 16-byte tag, i.e. bytes 48-217 of
	// the wire record. The 16-byte identity hash and 32-byte ephemeral key that
	// precede it are cleartext framing written by the caller.
	ShortBuildRequestEncryptedSize = ShortBuildRequestSize + BuildTagSize // 170
	// ShortBuildReplyEncryptedSize is the AEAD output for a short reply record,
	// which has no cleartext prefix and so fills the whole 218-byte record.
	ShortBuildReplyEncryptedSize = ShortBuildReplySize + BuildTagSize // 218

	// LongBuildRequestSize is the deprecated long BuildRequestRecord plaintext
	// length (spec: "Unencrypted size: 464 bytes").
	LongBuildRequestSize = 464
	// LongBuildReplySize is the deprecated long BuildReplyRecord plaintext length
	// (spec: "Unencrypted size: 512 bytes").
	LongBuildReplySize = 512
	// LongBuildRecordSize is the complete on-wire long record (spec: "Encrypted
	// BuildRequestRecords are 528 bytes for both ElGamal and ECIES").
	LongBuildRecordSize = 528
	// LongBuildRequestEncryptedSize is the AEAD output for a long request record
	// (464 + 16), i.e. bytes 48-527 of the wire record.
	LongBuildRequestEncryptedSize = LongBuildRequestSize + BuildTagSize // 480
	// LongBuildReplyEncryptedSize is the AEAD output for a long reply record.
	LongBuildReplyEncryptedSize = LongBuildReplySize + BuildTagSize // 528

	// BuildNonceSize is the ChaCha20-Poly1305 nonce length used for build
	// records: "12 byte nonce, with the first 4 bytes set to zero."
	BuildNonceSize = 12
	// BuildTagSize is the Poly1305 authentication tag length.
	BuildTagSize = 16

	// MaxBuildRecords is the number of records in a tunnel build message whose
	// reply encryption uses the record number as the nonce ("n = record number
	// 0-7").
	MaxBuildRecords = 8

	// TruncatedIdentityHashSize is the 16-byte hop identity-hash prefix that
	// identifies which record belongs to which hop. The caller writes it; it is
	// not part of the AEAD input.
	TruncatedIdentityHashSize = 16
	// EphemeralPublicKeySize is the sender's X25519 ephemeral public key written
	// in cleartext ahead of the encrypted record.
	EphemeralPublicKeySize = 32
)

// buildProtocolName is the Noise protocol name for tunnel build request
// encryption. Unlike the end-to-end ECIES protocol name, this one is NOT hashed
// into h at initialization: the spec pads it to 32 bytes instead.
const buildProtocolName = "Noise_N_25519_ChaChaPoly_SHA256"

// Errors for Tunnel-Creation-ECIES build record operations.
var (
	ErrBuildRecordSize    = oops.Errorf("build record has unexpected size")
	ErrBuildKeySize       = oops.Errorf("build record key has unexpected size")
	ErrBuildKeyDerivation = oops.Errorf("build record key derivation failed")
	ErrBuildAEAD          = oops.Errorf("build record AEAD failed")
)

// BuildNoiseState is the Noise_N symmetric state (chaining key ck and handshake
// hash h) for encrypting or decrypting tunnel build records to a hop.
//
// It is initialized exactly as the spec's "KDF for Initial ck and h" requires:
//
//	protocol_name = "Noise_N_25519_ChaChaPoly_SHA256"  (31 bytes)
//	h = protocol_name || 0                  // pad to 32 bytes, do NOT hash
//	ck = h                                  // copy
//	h = SHA256(h)                           // MixHash(null prologue)
//
// The pre-computed part depends only on the protocol name, so every router can
// cache it; the per-hop steps are added with [BuildNoiseState.MixHash].
type BuildNoiseState struct {
	ck [32]byte // chaining key
	h  [32]byte // handshake hash, used as AEAD associated data
}

// NewBuildNoiseState returns the initial Noise_N state shared by all build
// requests, before any hop-specific keys are mixed in.
func NewBuildNoiseState() *BuildNoiseState {
	// Pad the 31-byte protocol name with a single zero byte to 32 bytes. The
	// spec is explicit: "Pad to 32 bytes. Do NOT hash it, because it is not more
	// than 32 bytes."
	var padded [32]byte
	copy(padded[:], buildProtocolName)

	s := &BuildNoiseState{h: padded, ck: padded}
	// MixHash(null prologue).
	s.h = sha256.Sum256(s.h[:])
	return s
}

// MixHash mixes d into the handshake hash: h = SHA-256(h || d).
func (s *BuildNoiseState) MixHash(d []byte) {
	buf := make([]byte, 0, 64)
	buf = append(buf, s.h[:]...)
	buf = append(buf, d...)
	s.h = sha256.Sum256(buf)
}

// Hash returns the current handshake hash h, which is the AEAD associated data
// for the record encrypted at this state.
func (s *BuildNoiseState) Hash() [32]byte { return s.h }

// ChainKey returns the current chaining key ck. After a request record has been
// encrypted/decrypted this is the root of the reply/layer key KDF chain.
func (s *BuildNoiseState) ChainKey() [32]byte { return s.ck }

// MixKey performs the Noise MixKey step for a DH result:
//
//	keydata = HKDF(salt=ck, ikm=sharedSecret, info="", 64)
//	ck      = keydata[0:32]
//	k       = keydata[32:64]
//
// It returns the encryption key k for the next record and advances ck. The spec
// writes this as HKDF(chainKey, sharedSecret, "", 64); kdf.StandardHKDF takes
// (salt, ikm, info, n), so ck is the salt and the DH output is the ikm.
func (s *BuildNoiseState) MixKey(sharedSecret []byte) (k [32]byte, err error) {
	keydata, err := kdf.StandardHKDF(s.ck[:], sharedSecret, nil, 64)
	if err != nil {
		return k, oops.Wrapf(ErrBuildKeyDerivation, "MixKey HKDF failed: %w", err)
	}
	copy(s.ck[:], keydata[0:32])
	copy(k[:], keydata[32:64])
	clear(keydata)
	return k, nil
}

// EncryptBuildRequest encrypts a serialized BuildRequestRecord to a hop using the
// Noise_N "es" pattern.
//
// The caller supplies:
//   - hopStaticPub: the hop's X25519 static public key from its Router Identity
//     (mixed into h before the DH)
//   - senderPriv / senderPub: a fresh ephemeral X25519 key pair, unique per ECIES
//     hop AND per build record. The spec warns: "Ephemeral keys must be unique
//     per ECIES hop, and per build record. Failing to use unique keys opens an
//     attack vector for colluding hops to confirm they are in the same tunnel."
//   - plaintext: the serialized record, 154 bytes (short) or 464 bytes (long)
//
// It returns the 16-byte cleartext prefix (hop hash + sender public key) is NOT
// produced here - the caller writes those - and only the encrypted region plus
// tag is returned, which is len(plaintext)+16 bytes.
func EncryptBuildRequest(
	state *BuildNoiseState,
	hopStaticPub, senderPriv, senderPub, plaintext []byte,
) (ciphertext []byte, err error) {
	if state == nil {
		return nil, oops.Errorf("nil build Noise state")
	}
	if len(hopStaticPub) != EphemeralPublicKeySize {
		return nil, oops.Wrapf(ErrBuildKeySize, "hop static key must be %d bytes, got %d", EphemeralPublicKeySize, len(hopStaticPub))
	}
	if len(senderPub) != EphemeralPublicKeySize || len(senderPriv) != EphemeralPublicKeySize {
		return nil, oops.Wrapf(ErrBuildKeySize, "sender ephemeral key pair must be %d bytes each", EphemeralPublicKeySize)
	}
	if err := checkBuildRequestPlaintextSize(plaintext); err != nil {
		return nil, err
	}

	// MixHash(hepk) then MixHash(sepk).
	state.MixHash(hopStaticPub)
	state.MixHash(senderPub)

	// sharedSecret = DH(sesk, hepk)
	sharedSecret, err := curve25519.X25519(senderPriv, hopStaticPub)
	if err != nil {
		return nil, oops.Wrapf(ErrBuildKeyDerivation, "X25519 DH failed: %w", err)
	}

	k, err := state.MixKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	ad := state.Hash()
	ct, err := sealBuildRecord(k, ad, plaintext, 0)
	if err != nil {
		return nil, err
	}

	// MixHash(ciphertext) - feeds the reply record KDF and updates h.
	state.MixHash(ct)
	return ct, nil
}

// DecryptBuildRequest decrypts a BuildRequestRecord at a hop. The hop uses its
// own static private key and the sender's cleartext ephemeral public key read
// from bytes 16-47 of the record.
func DecryptBuildRequest(
	state *BuildNoiseState,
	hopStaticPriv, senderPub, ciphertext []byte,
) (plaintext []byte, err error) {
	if state == nil {
		return nil, oops.Errorf("nil build Noise state")
	}
	if len(hopStaticPriv) != EphemeralPublicKeySize {
		return nil, oops.Wrapf(ErrBuildKeySize, "hop static private key must be %d bytes, got %d", EphemeralPublicKeySize, len(hopStaticPriv))
	}
	if len(senderPub) != EphemeralPublicKeySize {
		return nil, oops.Wrapf(ErrBuildKeySize, "sender ephemeral public key must be %d bytes, got %d", EphemeralPublicKeySize, len(senderPub))
	}
	if err := checkBuildRequestCiphertextSize(ciphertext); err != nil {
		return nil, err
	}

	// The receiver must derive its own public key to mix in, matching the
	// sender's MixHash(hepk) step.
	hopStaticPub, err := curve25519.X25519(hopStaticPriv, curve25519.Basepoint)
	if err != nil {
		return nil, oops.Wrapf(ErrBuildKeyDerivation, "failed to derive hop static public key: %w", err)
	}
	state.MixHash(hopStaticPub)
	state.MixHash(senderPub)

	// sharedSecret = DH(hesk, sepk)
	sharedSecret, err := curve25519.X25519(hopStaticPriv, senderPub)
	if err != nil {
		return nil, oops.Wrapf(ErrBuildKeyDerivation, "X25519 DH failed: %w", err)
	}

	k, err := state.MixKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	ad := state.Hash()
	pt, err := openBuildRecord(k, ad, ciphertext, 0)
	if err != nil {
		return nil, err
	}

	state.MixHash(ciphertext)
	return pt, nil
}

// BuildReplyKeys are the keys derived from the chaining key after a build
// request has been processed, per the spec's "KDF" section.
type BuildReplyKeys struct {
	// ReplyKey encrypts this hop's own reply record with ChaCha20-Poly1305 and
	// obfuscates the other records with the raw ChaCha20 stream. Both use the
	// same key.
	ReplyKey [32]byte
	// LayerKey is the AES-256 tunnel layer key (layer encryption type 0).
	LayerKey [32]byte
	// IVKey is the AES-256 tunnel IV key.
	IVKey [32]byte
	// GarlicReplyKey and GarlicReplyTag are only meaningful for the outbound
	// endpoint (OBEP); they key the garlic-encrypted reply.
	GarlicReplyKey [32]byte
	GarlicReplyTag [8]byte
	// ChainKey is the chaining key after the KDF chain, for any further use.
	ChainKey [32]byte
}

// DeriveBuildReplyKeys runs the Tunnel-Creation-ECIES reply/layer KDF chain on
// the chaining key left in state after the build request was encrypted or
// decrypted.
//
// The chain differs for the OBEP, which is why isOBEP is a parameter (spec: "The
// KDF for the IV key at the OBEP is different from that for the other hops, even
// if the reply is not garlic encrypted"):
//
//	keydata = HKDF(ck, ZEROLEN, "SMTunnelReplyKey", 64)
//	replyKey = keydata[32:64]; ck = keydata[0:32]
//	keydata = HKDF(ck, ZEROLEN, "SMTunnelLayerKey", 64)
//	layerKey = keydata[32:64]
//	  non-OBEP: ivKey = keydata[0:32]              ("because it's last")
//	  OBEP:     ck = keydata[0:32]
//	            keydata = HKDF(ck, ZEROLEN, "TunnelLayerIVKey", 64)
//	            ivKey = keydata[32:64]; ck = keydata[0:32]
//	            keydata = HKDF(ck, ZEROLEN, "RGarlicKeyAndTag", 64)
//	            garlicReplyKey = keydata[32:64]; garlicReplyTag = keydata[0:8]
//
// Note on slices: the spec writes its ranges inclusively ("keydata[0:31]" means
// the 32 bytes at indices 0..31), so keydata[0:7] is the 8-byte garlic reply tag
// - consistent with the spec's own "32-byte garlic reply key and 8-byte garlic
// reply tag".
func DeriveBuildReplyKeys(state *BuildNoiseState, isOBEP bool) (BuildReplyKeys, error) {
	var out BuildReplyKeys
	if state == nil {
		return out, oops.Errorf("nil build Noise state")
	}
	ck := state.ChainKey()

	keydata, err := kdf.StandardHKDF(ck[:], nil, []byte("SMTunnelReplyKey"), 64)
	if err != nil {
		return out, oops.Wrapf(ErrBuildKeyDerivation, "SMTunnelReplyKey failed: %w", err)
	}
	copy(out.ReplyKey[:], keydata[32:64])
	copy(ck[:], keydata[0:32])

	keydata, err = kdf.StandardHKDF(ck[:], nil, []byte("SMTunnelLayerKey"), 64)
	if err != nil {
		return out, oops.Wrapf(ErrBuildKeyDerivation, "SMTunnelLayerKey failed: %w", err)
	}
	copy(out.LayerKey[:], keydata[32:64])

	if isOBEP {
		copy(ck[:], keydata[0:32])

		keydata, err = kdf.StandardHKDF(ck[:], nil, []byte("TunnelLayerIVKey"), 64)
		if err != nil {
			return out, oops.Wrapf(ErrBuildKeyDerivation, "TunnelLayerIVKey failed: %w", err)
		}
		copy(out.IVKey[:], keydata[32:64])
		copy(ck[:], keydata[0:32])

		keydata, err = kdf.StandardHKDF(ck[:], nil, []byte("RGarlicKeyAndTag"), 64)
		if err != nil {
			return out, oops.Wrapf(ErrBuildKeyDerivation, "RGarlicKeyAndTag failed: %w", err)
		}
		copy(out.GarlicReplyKey[:], keydata[32:64])
		copy(out.GarlicReplyTag[:], keydata[0:8])
	} else {
		// Non-OBEP: the left half is the IV key and the chain stops here.
		copy(out.IVKey[:], keydata[0:32])
	}

	out.ChainKey = ck
	clear(keydata)
	return out, nil
}

// EncryptOwnBuildReply encrypts this hop's own BuildReplyRecord with
// ChaCha20-Poly1305. 'ad' is the handshake hash h left over from the build
// request.
//
// The AEAD nonce 'n' depends on the record size and is derived here rather than
// taken from recordNumber blindly, because the two formats differ:
//
//   - Short (202-byte plaintext): §Record Encryption - "'n' is the record number
//     0-7". recordNumber is used.
//   - Long (512-byte plaintext, deprecated): §Reply Record Encryption - "n = 0".
//     The record number is ignored and the nonce is always zero.
//
// Passing a non-zero recordNumber with a long record would produce bytes a
// 0.9.48-era router cannot open, so the size, not the caller, decides.
func EncryptOwnBuildReply(replyKey, ad [32]byte, recordNumber byte, plaintext []byte) ([]byte, error) {
	if err := checkBuildReplyPlaintextSize(plaintext); err != nil {
		return nil, err
	}
	return sealBuildRecord(replyKey, ad, plaintext, uint64(replyNonce(recordNumber, len(plaintext))))
}

// DecryptOwnBuildReply decrypts a hop's own reply record, applying the same
// size-derived nonce rule as [EncryptOwnBuildReply].
func DecryptOwnBuildReply(replyKey, ad [32]byte, recordNumber byte, ciphertext []byte) ([]byte, error) {
	if err := checkBuildReplyCiphertextSize(ciphertext); err != nil {
		return nil, err
	}
	// The AEAD output is plaintext+BuildTagSize; recover the plaintext length so
	// the long/short nonce rule keys off the same value encryption used.
	return openBuildRecord(replyKey, ad, ciphertext, uint64(replyNonce(recordNumber, len(ciphertext)-BuildTagSize)))
}

// replyNonce returns the ChaCha20-Poly1305 build reply nonce for a record of the
// given plaintext length: always 0 for the deprecated 512-byte long record, the
// record number for the 202-byte short record. See [EncryptOwnBuildReply].
func replyNonce(recordNumber byte, plaintextSize int) byte {
	if plaintextSize == LongBuildReplySize {
		return 0
	}
	return recordNumber
}

// ObfuscateOtherBuildRecord applies the raw ChaCha20 stream to another hop's
// already-encrypted 218-byte short record, as each hop does iteratively on the
// reply path. This is deliberately unauthenticated ("ChaCha20 (NOT
// ChaCha20/Poly1305)"), and the record number goes in IV byte 4.
//
// Encryption and decryption are the same XOR operation, so a hop that received a
// record obfuscated with its reply key simply calls this again to undo it.
//
// Only short (218-byte) records are accepted. The deprecated long-record format
// obfuscates the other records with AES and does not use the record number
// (tunnel-creation-ecies.md §Record Encryption: "This is different from the long
// record specification above, which uses AES and does not use the record
// number"). That is a different scheme, not implemented here, so a 528-byte
// record is rejected rather than silently ChaCha20-obfuscated into bytes a legacy
// router cannot unmask.
func ObfuscateOtherBuildRecord(replyKey [32]byte, recordNumber byte, record []byte) ([]byte, error) {
	if err := checkBuildRecordSize(record); err != nil {
		return nil, err
	}
	if len(record) == LongBuildRecordSize {
		return nil, oops.Wrapf(ErrBuildRecordSize,
			"long (528-byte) records use AES obfuscation without a record number, not ChaCha20; this function only handles short 218-byte records")
	}
	iv, err := buildRecordIV(recordNumber)
	if err != nil {
		return nil, err
	}
	return chacha20.StreamEncrypt(replyKey[:], iv, record)
}

// sealBuildRecord encrypts plaintext with ChaCha20-Poly1305 using the spec's
// nonce layout, returning ciphertext||tag.
func sealBuildRecord(k, ad [32]byte, plaintext []byte, counter uint64) ([]byte, error) {
	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, oops.Wrapf(ErrBuildAEAD, "failed to create build AEAD: %w", err)
	}
	return aead.Seal(nil, buildNonce(counter), plaintext, ad[:]), nil
}

// openBuildRecord decrypts ciphertext||tag produced by sealBuildRecord.
func openBuildRecord(k, ad [32]byte, ciphertext []byte, counter uint64) ([]byte, error) {
	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, oops.Wrapf(ErrBuildAEAD, "failed to create build AEAD: %w", err)
	}
	pt, err := aead.Open(nil, buildNonce(counter), ciphertext, ad[:])
	if err != nil {
		return nil, oops.Wrapf(ErrBuildAEAD, "build record authentication failed: %w", err)
	}
	return pt, nil
}

// buildNonce builds the 12-byte ChaCha20-Poly1305 nonce: "12 byte nonce, with
// the first 4 bytes set to zero", the counter in the remaining 8 bytes
// little-endian.
func buildNonce(counter uint64) []byte {
	nonce := make([]byte, BuildNonceSize)
	// First 4 bytes are zero per the spec.
	nonce[4] = byte(counter)
	nonce[5] = byte(counter >> 8)
	nonce[6] = byte(counter >> 16)
	nonce[7] = byte(counter >> 24)
	nonce[8] = byte(counter >> 32)
	nonce[9] = byte(counter >> 40)
	nonce[10] = byte(counter >> 48)
	nonce[11] = byte(counter >> 56)
	return nonce
}

// buildRecordIV builds the raw-ChaCha20 IV for reply obfuscation: 12 zero bytes
// with the record number at byte 4.
func buildRecordIV(recordNumber byte) ([]byte, error) {
	if recordNumber >= MaxBuildRecords {
		return nil, oops.Wrapf(ErrBuildRecordSize, "record number %d out of range 0-%d", recordNumber, MaxBuildRecords-1)
	}
	iv := make([]byte, BuildNonceSize)
	iv[4] = recordNumber
	return iv, nil
}

// checkBuildRequestPlaintextSize accepts exactly the spec-defined BuildRequestRecord
// plaintext sizes: 154 (short) or 464 (long).
func checkBuildRequestPlaintextSize(plaintext []byte) error {
	switch len(plaintext) {
	case ShortBuildRequestSize, LongBuildRequestSize:
		return nil
	default:
		return oops.Wrapf(ErrBuildRecordSize,
			"build request plaintext must be %d (short) or %d (long) bytes, got %d",
			ShortBuildRequestSize, LongBuildRequestSize, len(plaintext))
	}
}

// checkBuildReplyPlaintextSize accepts exactly the spec-defined BuildReplyRecord
// plaintext sizes: 202 (short) or 512 (long).
func checkBuildReplyPlaintextSize(plaintext []byte) error {
	switch len(plaintext) {
	case ShortBuildReplySize, LongBuildReplySize:
		return nil
	default:
		return oops.Wrapf(ErrBuildRecordSize,
			"build reply plaintext must be %d (short) or %d (long) bytes, got %d",
			ShortBuildReplySize, LongBuildReplySize, len(plaintext))
	}
}

// checkBuildRequestCiphertextSize accepts the AEAD output for a request record:
// plaintext plus the 16-byte Poly1305 tag (170 short, 480 long). The 48-byte
// cleartext prefix is not part of this value.
func checkBuildRequestCiphertextSize(ciphertext []byte) error {
	switch len(ciphertext) {
	case ShortBuildRequestEncryptedSize, LongBuildRequestEncryptedSize:
		return nil
	default:
		return oops.Wrapf(ErrBuildRecordSize,
			"build request ciphertext must be %d (short) or %d (long) bytes, got %d",
			ShortBuildRequestEncryptedSize, LongBuildRequestEncryptedSize, len(ciphertext))
	}
}

// checkBuildReplyCiphertextSize accepts the AEAD output for a reply record
// (218 short, 528 long). A reply has no cleartext prefix, so the short reply
// ciphertext is the whole 218-byte wire record.
func checkBuildReplyCiphertextSize(ciphertext []byte) error {
	switch len(ciphertext) {
	case ShortBuildReplyEncryptedSize, LongBuildReplyEncryptedSize:
		return nil
	default:
		return oops.Wrapf(ErrBuildRecordSize,
			"build reply ciphertext must be %d (short) or %d (long) bytes, got %d",
			ShortBuildReplyEncryptedSize, LongBuildReplyEncryptedSize, len(ciphertext))
	}
}

// checkBuildRecordSize accepts a complete encrypted record of either length, for
// the raw-ChaCha20 obfuscation applied to records belonging to other hops.
func checkBuildRecordSize(record []byte) error {
	switch len(record) {
	case ShortBuildRecordSize, LongBuildRecordSize:
		return nil
	default:
		return oops.Wrapf(ErrBuildRecordSize,
			"build record must be %d (short) or %d (long) bytes, got %d",
			ShortBuildRecordSize, LongBuildRecordSize, len(record))
	}
}
