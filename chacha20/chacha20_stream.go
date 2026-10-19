package chacha20

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	xchacha20 "golang.org/x/crypto/chacha20"
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

// StreamEncrypt encrypts plaintext with the unauthenticated ChaCha20 stream
// cipher (RFC 7539 section 2.4), using a 32-byte key and a 12-byte IV/nonce.
// The output is exactly len(plaintext) bytes; ChaCha20 is a stream cipher, so
// there is no padding and no authentication tag.
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

	cipher, err := xchacha20.NewUnauthenticatedCipher(key, iv)
	if err != nil {
		return nil, oops.Wrapf(ErrEncryptFailed, "failed to create ChaCha20 stream cipher: %w", err)
	}

	out := make([]byte, len(plaintext))
	cipher.XORKeyStream(out, plaintext)
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
