package ecies

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/go-i2p/crypto/elligator2"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// noiseProtocolName is the Noise protocol name for the one-time (IK) pattern
// used by I2P ECIES-X25519-AEAD.
//
// Spec: https://i2p.net/en/docs/specs/ecies/ (section 1f, "Key Derivation")
const noiseProtocolName = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"

// oneTimeCiphertextOverhead is the number of bytes of overhead added to the
// plaintext by the one-time ECIES-X25519-AEAD format:
//
//	[Elligator2-encoded ephemeral public key 32]
//	[flags section: ChaCha20 ciphertext 32 + Poly1305 tag 16]
//	[payload section: Poly1305 tag 16]
//
// = 32 + 48 + 16 = 96 bytes.
const oneTimeCiphertextOverhead = 96

// flagsSectionSize is the size of the (decrypted) flags section in the
// one-time format. The decrypted flags are 32 bytes of all zeros for the
// one-time format.
const flagsSectionSize = 32

// EncryptECIESX25519 encrypts data using the I2P ECIES-X25519-AEAD one-time
// format.
//
// The ciphertext layout (spec section 1d) is:
//
//	[Elligator2-encoded ephemeral public key 32 bytes]
//	[flags section: ChaCha20 ciphertext 32 bytes + Poly1305 tag 16 bytes]
//	[payload section: ChaCha20 ciphertext N bytes + Poly1305 tag 16 bytes]
//
// The key schedule follows the Noise "IK" + "es" + "N" patterns (spec
// section 1f):
//
//	protocol_name = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"
//	h = SHA256(protocol_name)
//	chainKey = h
//	h = SHA256(h)                       // MixHash with empty prologue
//	h = SHA256(h || bpk)                // MixHash with Bob's static public key
//	h = SHA256(h || aepk)               // MixHash with Alice's ephemeral public key
//	sharedSecret = DH(aesk, bpk)
//	keydata = HKDF(salt=chainKey, ikm=sharedSecret, info="", 64)
//	k = keydata[32:64]
//
// The flags section encrypts 32 bytes of all zeros with nonce 0 and
// associated data h; the payload is then encrypted with nonce 1 and the
// updated h. Both sections use the same key k.
//
// Parameters:
//   - recipientPubKey: The recipient's 32-byte X25519 public key (Bob's static key)
//   - plaintext: The data to encrypt
//
// Returns:
//   - ciphertext: The encrypted data in the one-time format
//   - error: Any error during encryption
func EncryptECIESX25519(recipientPubKey, plaintext []byte) ([]byte, error) {
	if len(recipientPubKey) != PublicKeySize {
		return nil, oops.Wrapf(ErrInvalidPublicKey, "public key must be %d bytes, got %d", PublicKeySize, len(recipientPubKey))
	}
	if len(plaintext) > MaxPlaintextSize {
		return nil, oops.Wrapf(ErrDataTooBig, "plaintext exceeds maximum size of %d bytes", MaxPlaintextSize)
	}

	// Generate an ephemeral X25519 key pair whose public key is
	// Elligator2-representable (spec section 2), and get the wire encoding in
	// the same pass. Spec section 2a Notes: "The generator does the ENCODE_ELG2()
	// function to determine suitability. Therefore, the generator should store the
	// result of ENCODE_ELG2() so it does not have to be calculated again."
	// GenerateEncodedKeyPair returns (publicKey, privateKey, encoded, error).
	aepk, aesk, encodedAepk, err := elligator2.GenerateEncodedKeyPair()
	if err != nil {
		return nil, oops.Wrapf(ErrKeyGenerationFailed, "failed to generate Elligator2-representable ephemeral key: %w", err)
	}

	// Run the Noise IK + es key schedule.
	h, k, err := deriveOneTimeKey(recipientPubKey, aesk, aepk, nil)
	if err != nil {
		return nil, err
	}

	// Encrypt the flags section (32 bytes of all zeros) with nonce 0.
	flagsCt, err := encryptSection(k, h, make([]byte, flagsSectionSize), 0)
	if err != nil {
		return nil, err
	}

	// MixHash with the flags ciphertext.
	//
	// Spec section 1f labels this MixHash under the "s" message pattern, and the
	// no-static-key path says only "ad = h from Flags/Static key section", so the
	// text is ambiguous about whether the mix happens when there is no static key
	// to send. It is done here because the flags section is a complete Noise
	// transport message (encrypted with k at n = 0) and Noise mixes every
	// transport message's ciphertext into h. The spec's own use of n = 1 for the
	// payload - the counter advance for a second transport message - is the
	// strongest available evidence that the payload is that second message, so h
	// must already include the flags ciphertext.
	//
	// Note that the "+hs2" in the protocol name does NOT settle this: section 1f
	// says it indicates "that MixHash() is called before the second message to
	// mix in the tag value", and the tag mix is the MixHash(tag) step in the New
	// Session Reply path, not this one.
	//
	// TODO(spec): confirm against a reference implementation (Java ECIESOneTime /
	// i2pd) and add a known-answer vector for the one-time format. If the mix is
	// wrong, every one-time message fails to interoperate.
	h = sha256.Sum256(append(h[:], flagsCt...))

	// Encrypt the payload with nonce 1.
	payloadCt, err := encryptSection(k, h, plaintext, 1)
	if err != nil {
		return nil, err
	}

	// Assemble: [encodedAepk 32][flagsCt 48][payloadCt N+16]
	ciphertext := make([]byte, 0, len(encodedAepk)+len(flagsCt)+len(payloadCt))
	ciphertext = append(ciphertext, encodedAepk...)
	ciphertext = append(ciphertext, flagsCt...)
	ciphertext = append(ciphertext, payloadCt...)

	return ciphertext, nil
}

// DecryptECIESX25519 decrypts data using the I2P ECIES-X25519-AEAD one-time
// format produced by EncryptECIESX25519.
//
// Parameters:
//   - recipientPrivKey: The recipient's 32-byte X25519 private key (Bob's static key)
//   - ciphertext: The encrypted data in the one-time format
//
// Returns:
//   - plaintext: The decrypted data
//   - error: Any error during decryption
func DecryptECIESX25519(recipientPrivKey, ciphertext []byte) ([]byte, error) {
	if len(recipientPrivKey) != PrivateKeySize {
		return nil, oops.Wrapf(ErrInvalidPrivateKey, "private key must be %d bytes, got %d", PrivateKeySize, len(recipientPrivKey))
	}
	if len(ciphertext) < oneTimeCiphertextOverhead {
		return nil, oops.Wrapf(ErrInvalidCiphertext, "ciphertext too short: %d bytes, minimum %d", len(ciphertext), oneTimeCiphertextOverhead)
	}
	// Reject frames larger than the spec's maximum. ecies.md §"Unencrypted data":
	// "Encrypted data is 65535 bytes max, including a 16-byte authentication
	// header, so the max unencrypted data is 65519 bytes. Maximum ChaChaPoly
	// frame is 65535 bytes." The payload frame is at most MaxPlaintextSize+TagSize
	// = 65535; adding the 96-byte one-time overhead (elligator key + flags
	// section + payload tag) gives a receive-side ceiling of 65615. Without this
	// bound, arbitrarily large input is allocated and fed to the AEAD, a DoS
	// surface, and oversized frames the spec says must not exist are accepted.
	if maxCiphertext := oneTimeCiphertextOverhead + MaxPlaintextSize; len(ciphertext) > maxCiphertext {
		return nil, oops.Wrapf(ErrInvalidCiphertext, "ciphertext too long: %d bytes, maximum %d", len(ciphertext), maxCiphertext)
	}

	// Split the ciphertext into its components.
	encodedAepk := ciphertext[:PublicKeySize]
	flagsCt := ciphertext[PublicKeySize : PublicKeySize+flagsSectionSize+TagSize]
	payloadCt := ciphertext[PublicKeySize+flagsSectionSize+TagSize:]

	// Elligator2-decode the ephemeral public key.
	aepk, err := elligator2.Decode(encodedAepk)
	if err != nil {
		return nil, oops.Wrapf(ErrInvalidCiphertext, "failed to Elligator2-decode ephemeral public key: %w", err)
	}

	// Derive Bob's static public key from his private key for the MixHash step.
	bpk, err := curve25519.X25519(recipientPrivKey, curve25519.Basepoint)
	if err != nil {
		return nil, oops.Wrapf(ErrInvalidPrivateKey, "failed to derive public key from private key: %w", err)
	}

	// Run the same Noise IK + es key schedule as the sender.
	h, k, err := deriveOneTimeKey(bpk, nil, aepk, recipientPrivKey)
	if err != nil {
		return nil, err
	}

	// Decrypt the flags section with nonce 0 and verify it is all zeros
	// (the one-time format marker).
	flags, err := decryptSection(k, h, flagsCt, 0)
	if err != nil {
		return nil, oops.Wrapf(ErrDecryptionFailed, "flags section authentication failed: %w", err)
	}
	if !isAllZeros(flags) {
		return nil, oops.Wrapf(ErrDecryptionFailed, "flags section is not all zeros; not a one-time message")
	}

	// MixHash with the flags ciphertext.
	h = sha256.Sum256(append(h[:], flagsCt...))

	// Decrypt the payload with nonce 1.
	plaintext, err := decryptSection(k, h, payloadCt, 1)
	if err != nil {
		return nil, oops.Wrapf(ErrDecryptionFailed, "payload authentication failed: %w", err)
	}

	return plaintext, nil
}

// deriveOneTimeKey runs the Noise "IK" + "es" key schedule for the one-time
// format and returns the final hash h and the message key k.
//
// Parameters:
//   - bpk: Bob's static PUBLIC key (always used for the MixHash step)
//   - aesk: Alice's ephemeral private key (set on the encrypt path, nil on the
//     decrypt path)
//   - aepk: Alice's ephemeral public key (decoded, not Elligator2-encoded)
//   - besk: Bob's static private key (set on the decrypt path, nil on the
//     encrypt path)
//
// The DH step is DH(aesk, bpk) on the encrypt path and DH(besk, aepk) on the
// decrypt path; both yield the same shared secret.
func deriveOneTimeKey(bpk, aesk, aepk, besk []byte) (h [32]byte, k [32]byte, err error) {
	// h = SHA256(protocol_name); chainKey = h
	protocolHash := sha256.Sum256([]byte(noiseProtocolName))
	chainKey := protocolHash

	// h = SHA256(h)  (MixHash with empty prologue)
	h = sha256.Sum256(protocolHash[:])

	// h = SHA256(h || bpk)  (MixHash with Bob's static public key)
	h = sha256.Sum256(append(h[:], bpk...))

	// h = SHA256(h || aepk)  (MixHash with Alice's ephemeral public key)
	h = sha256.Sum256(append(h[:], aepk...))

	// "es": sharedSecret = DH(aesk, bpk) on encrypt, DH(besk, aepk) on decrypt.
	var sharedSecret []byte
	if aesk != nil {
		sharedSecret, err = curve25519.X25519(aesk, bpk)
	} else {
		sharedSecret, err = curve25519.X25519(besk, aepk)
	}
	if err != nil {
		return [32]byte{}, [32]byte{}, oops.Wrapf(ErrKeyDerivationFailed, "X25519 key agreement failed: %w", err)
	}

	// keydata = HKDF(salt=chainKey, ikm=sharedSecret, info="", 64)
	// k = keydata[32:64]
	keydata, err := hkdfDerive(sharedSecret, chainKey[:], nil, 64)
	if err != nil {
		return [32]byte{}, [32]byte{}, oops.Wrapf(ErrKeyDerivationFailed, "Noise MixKey failed: %w", err)
	}
	copy(k[:], keydata[32:64])

	return h, k, nil
}

// hkdfDerive derives keyLen bytes using HKDF-SHA256 with the given ikm, salt
// and info.
func hkdfDerive(ikm, salt, info []byte, keyLen int) ([]byte, error) {
	reader := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, keyLen)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, oops.Wrapf(ErrKeyDerivationFailed, "HKDF derivation failed: %w", err)
	}
	return out, nil
}

// encryptSection encrypts a section with ChaCha20-Poly1305 using the spec's
// 12-byte nonce (first 4 bytes zero, last 8 bytes the little-endian counter)
// and the given associated data.
//
// Returns the ciphertext concatenated with the 16-byte Poly1305 tag.
func encryptSection(k [32]byte, h [32]byte, plaintext []byte, counter uint64) ([]byte, error) {
	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, oops.Wrapf(ErrEncryptionFailed, "failed to create AEAD: %w", err)
	}

	// Seal appends the 16-byte tag to the ciphertext.
	return aead.Seal(nil, makeNonce(counter), plaintext, h[:]), nil
}

// decryptSection decrypts a section with ChaCha20-Poly1305. The wire format
// is ciphertext followed by the 16-byte Poly1305 tag.
func decryptSection(k [32]byte, h [32]byte, wire []byte, counter uint64) ([]byte, error) {
	if len(wire) < TagSize {
		return nil, oops.Wrapf(ErrInvalidCiphertext, "section too short: %d bytes", len(wire))
	}

	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, oops.Wrapf(ErrDecryptionFailed, "failed to create AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, makeNonce(counter), wire, h[:])
	if err != nil {
		return nil, oops.Wrapf(ErrDecryptionFailed, "ChaCha20-Poly1305 decryption failed: %w", err)
	}

	return plaintext, nil
}

// makeNonce builds the spec's 12-byte ChaCha20-Poly1305 nonce: the first 4
// bytes are zero and the last 8 bytes are the little-endian counter.
func makeNonce(counter uint64) []byte {
	nonce := make([]byte, NonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// isAllZeros reports whether every byte in b is zero.
func isAllZeros(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// GenerateKeyPair generates a new X25519 key pair suitable for ECIES-X25519.
// Returns (publicKey, privateKey, error) where keys are 32 bytes each.
func GenerateKeyPair() ([]byte, []byte, error) {
	pub, priv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, oops.Wrapf(ErrKeyGenerationFailed, "failed to generate X25519 key pair: %w", err)
	}

	// Return copies to prevent external modification
	pubKey := make([]byte, PublicKeySize)
	privKey := make([]byte, PrivateKeySize)
	copy(pubKey, pub[:])
	copy(privKey, priv[:])

	return pubKey, privKey, nil
}
