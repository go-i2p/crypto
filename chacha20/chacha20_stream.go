package chacha20

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	chacha20rfc "golang.org/x/crypto/chacha20"
)

// This file provides the unauthenticated ChaCha20 stream cipher, distinct from
// the ChaCha20-Poly1305 AEAD implemented by ChaCha20Poly{Encrypter,Decrypter}.
//
// It is required by the I2P Tunnel-Creation-ECIES specification
// (https://i2p.net/en/docs/specs/tunnel-creation-ecies/), whose "Cryptographic
// Primitives" section lists, separately from the AEAD:
//
//	"STREAM ChaCha20 functions: ENCRYPT(k, iv, plaintext) and
//	 DECRYPT(k, iv, ciphertext)"
//
// The spec uses this raw stream at each hop to iteratively obfuscate the
// *other* build reply records in a Short Tunnel Build Message: "The other
// records are iteratively and symmetrically encrypted at each hop with ChaCha20
// (NOT ChaCha20/Poly1305)... The record number is put in the IV at byte 4,
// because ChaCha20 uses a 12-byte IV with a little-endian nonce at bytes 4-11."
// Because it is unauthenticated, callers must not rely on it for integrity - it
// is an obfuscation layer only; the hop's own record uses the AEAD instead.
//
// The block counter starts at 1, not 0. tunnel-creation-ecies.md defines STREAM
// "as in EncryptedLeaseSet and RFC-7539", and the Encrypted Lease Set spec
// (https://i2p.net/en/docs/specs/encryptedleaseset/, "Definitions") fixes it:
//
//	STREAM : The ChaCha20 stream cipher as specified in [RFC-7539-S2.4],
//	         with the initial counter set to 1. S_KEY_LEN = 32 and S_IV_LEN = 12.
//
// Starting at 0 shifts the keystream by one 64-byte block, so a Go peer would
// emit record bytes a Java peer cannot unmask. See [StreamInitialCounter].

// StreamInitialCounter is the ChaCha20 block counter the I2P "STREAM" primitive
// starts at. The Encrypted Lease Set spec (https://i2p.net/en/docs/specs/
// encryptedleaseset/, "Definitions") requires "the initial counter set to 1",
// which is what tunnel-creation-ecies.md's STREAM reference inherits. It is not
// RFC 7539's default of 0, so it has to be set explicitly.
const StreamInitialCounter = 1

// StreamEncrypt encrypts plaintext with the unauthenticated ChaCha20 stream
// cipher (RFC 7539 section 2.4), using a 32-byte key and a 12-byte IV/nonce,
// starting at block counter [StreamInitialCounter] as the I2P STREAM definition
// requires. The output is exactly len(plaintext) bytes; ChaCha20 is a stream
// cipher, so there is no padding and no authentication tag.
//
// Encryption and decryption are the same operation (XOR with the keystream), so
// StreamDecrypt is an alias for this function. The caller is responsible for the
// nonce: it MUST be unique for a given key. For the Tunnel-Creation-ECIES reply
// obfuscation the spec fixes the IV to 12 zero bytes with the record number in
// byte 4; use [StreamIVForRecord] to build it.
func StreamEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	log.WithFields(logger.Fields{
		"pkg":  "chacha20",
		"func": "StreamEncrypt",
	}).Debug("ChaCha20 stream encrypt")

	if len(key) != KeySize {
		return nil, oops.Wrapf(ErrInvalidKeySize, "key must be %d bytes, got %d", KeySize, len(key))
	}
	if len(iv) != NonceSize {
		return nil, oops.Wrapf(ErrInvalidNonceSize, "iv must be %d bytes, got %d", NonceSize, len(iv))
	}

	// NewUnauthenticatedCipher with a 12-byte nonce is RFC 7539 section 2.4
	// ChaCha20 (a 24-byte nonce would select XChaCha20, which I2P does not use).
	stream, err := chacha20rfc.NewUnauthenticatedCipher(key, iv)
	if err != nil {
		return nil, oops.Wrapf(ErrEncryptFailed, "failed to create ChaCha20 stream cipher: %w", err)
	}
	// RFC 7539 starts at counter 0; the I2P STREAM definition mandates 1.
	stream.SetCounter(StreamInitialCounter)

	out := make([]byte, len(plaintext))
	stream.XORKeyStream(out, plaintext)
	return out, nil
}

// StreamDecrypt decrypts ciphertext produced by [StreamEncrypt]. Identical to
// encryption for a stream cipher; provided for readability at call sites.
func StreamDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	return StreamEncrypt(key, iv, ciphertext)
}

// StreamIVForRecord builds the Tunnel-Creation-ECIES reply-obfuscation IV for a
// given record number: 12 bytes, all zero except byte 4, which holds the record
// number (0-7). This matches the spec's "iv = 12 bytes, all zeros except
// iv[4] = n". The record number must be in range 0-7; larger values are rejected
// because the spec only assigns one byte at offset 4 for the 8-record build
// message.
func StreamIVForRecord(recordNumber byte) (ChaCha20Nonce, error) {
	var iv ChaCha20Nonce
	// The spec's build message carries at most 8 records (n = 0-7). Reject
	// out-of-range numbers rather than silently wrapping in the single byte.
	if recordNumber > 7 {
		return iv, oops.Wrapf(ErrInvalidNonceSize, "record number %d out of range 0-7", recordNumber)
	}
	iv[4] = recordNumber
	return iv, nil
}
