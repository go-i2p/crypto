package chacha20

// Spec-vector tests for the unauthenticated STREAM ChaCha20.
//
// These are the only tests in this package that assert against externally
// generated values rather than round-tripping through our own code, so they are
// what actually pins the wire behaviour. The vector is RFC 7539 appendix A.2
// "ChaCha20 Encryption, Test Vector #2", whose initial block counter is 1 -
// precisely the counter the I2P STREAM primitive requires.

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// rfc7539TV2 returns RFC 7539 appendix A.2 "ChaCha20 Encryption, Test Vector
// #2" verbatim:
//
//	Key:                    00..00 01            (32 bytes)
//	Nonce:                  00 x11 02            (12 bytes)
//	Initial Block Counter = 1
func rfc7539TV2(t *testing.T) (key, nonce, plaintext, ciphertext []byte) {
	t.Helper()
	must := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("decode vector: %v", err)
		}
		return b
	}
	key = must("0000000000000000000000000000000000000000000000000000000000000001")
	nonce = must("000000000000000000000002")
	plaintext = must("416e79207375626d697373696f6e20746f20746865204945544620696e74656e" +
		"6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174" +
		"696f6e20617320616c6c206f722070617274206f6620616e204945544620496e746572" +
		"6e65742d4472616674206f722052464320616e6420616e792073746174656d656e7420" +
		"6d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620" +
		"616374697669747920697320636f6e7369646572656420616e20224945544620436f6e" +
		"747269627574696f6e222e20537563682073746174656d656e747320696e636c756465" +
		"206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c20" +
		"61732077656c6c206173207772697474656e20616e6420656c656374726f6e69632063" +
		"6f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f722070" +
		"6c6163652c207768696368206172652061646472657373656420746f")
	ciphertext = must("a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec" +
		"2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e0" +
		"2785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8" +
		"a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d6" +
		"62ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f7" +
		"6966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d528" +
		"0fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be" +
		"059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1" +
		"a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce091" +
		"1934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384d" +
		"d902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221")
	return key, nonce, plaintext, ciphertext
}

// TestStreamEncryptRFC7539Vector asserts that StreamEncrypt reproduces RFC 7539
// appendix A.2 Test Vector #2 over all 375 bytes. That vector's initial block
// counter is 1, which is the counter the I2P STREAM primitive mandates:
// tunnel-creation-ecies.md defines STREAM "as in EncryptedLeaseSet and
// RFC-7539", and the Encrypted Lease Set spec
// (https://i2p.net/en/docs/specs/encryptedleaseset/, "Definitions") states
//
//	STREAM : The ChaCha20 stream cipher as specified in [RFC-7539-S2.4],
//	         with the initial counter set to 1. S_KEY_LEN = 32 and S_IV_LEN = 12.
//
// Dropping SetCounter starts the keystream one 64-byte block earlier and this
// test fails at byte 0.
func TestStreamEncryptRFC7539Vector(t *testing.T) {
	key, nonce, plaintext, ciphertext := rfc7539TV2(t)

	got, err := StreamEncrypt(key, nonce, plaintext)
	if err != nil {
		t.Fatalf("StreamEncrypt: %v", err)
	}
	if len(got) != len(ciphertext) {
		t.Fatalf("output length %d, want %d", len(got), len(ciphertext))
	}
	if !bytes.Equal(got, ciphertext) {
		for i := range got {
			if got[i] != ciphertext[i] {
				t.Fatalf("keystream diverges at byte %d: got %02x, want %02x "+
					"(the block counter must start at 1 per the I2P STREAM definition)", i, got[i], ciphertext[i])
			}
		}
	}
}

// TestStreamEncryptNotCounterZero guards the exact regression using RFC 7539
// appendix A.2 Test Vector #1, which is the all-zero key, all-zero nonce stream
// at counter 0. With the counter set to 1 as I2P requires, those same inputs
// must produce something different.
func TestStreamEncryptNotCounterZero(t *testing.T) {
	// RFC 7539 A.2 Test Vector #1: key = 32 zero bytes, nonce = 12 zero bytes,
	// Initial Block Counter = 0, plaintext = 64 zero bytes. Its ciphertext is
	// therefore the counter-0 keystream.
	counter0Keystream, err := hex.DecodeString(
		"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" +
			"da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
	)
	if err != nil {
		t.Fatalf("decode vector: %v", err)
	}

	got, err := StreamEncrypt(make([]byte, KeySize), make([]byte, NonceSize), make([]byte, len(counter0Keystream)))
	if err != nil {
		t.Fatalf("StreamEncrypt: %v", err)
	}
	if bytes.Equal(got, counter0Keystream) {
		t.Error("StreamEncrypt starts at counter 0; the I2P STREAM definition requires counter 1")
	}
}

// TestStreamEncryptIsSelfInverse documents the stream property: encrypt and
// decrypt are the same XOR. This is a round-trip check and is deliberately NOT
// evidence of spec compliance - the vector tests above are.
func TestStreamEncryptIsSelfInverse(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	iv, err := StreamIVForRecord(3)
	if err != nil {
		t.Fatalf("StreamIVForRecord: %v", err)
	}
	msg := []byte("an obfuscated build reply record fragment")

	enc, err := StreamEncrypt(key, iv[:], msg)
	if err != nil {
		t.Fatalf("StreamEncrypt: %v", err)
	}
	if bytes.Equal(enc, msg) {
		t.Fatal("StreamEncrypt returned the plaintext unchanged")
	}
	dec, err := StreamDecrypt(key, iv[:], enc)
	if err != nil {
		t.Fatalf("StreamDecrypt: %v", err)
	}
	if !bytes.Equal(dec, msg) {
		t.Error("StreamDecrypt did not restore the plaintext")
	}
}

// TestStreamIVForRecord pins the reply-obfuscation IV layout required by
// tunnel-creation-ecies.md: 12 bytes, all zero except byte 4, which carries the
// record number ("The record number is put in the IV at byte 4, because ChaCha20
// uses a 12-byte IV with a little-endian nonce at bytes 4-11").
func TestStreamIVForRecord(t *testing.T) {
	for n := byte(0); n <= 7; n++ {
		iv, err := StreamIVForRecord(n)
		if err != nil {
			t.Fatalf("StreamIVForRecord(%d): %v", n, err)
		}
		for i, b := range iv {
			if i == 4 {
				if b != n {
					t.Errorf("record %d: iv[4] = %d, want %d", n, b, n)
				}
				continue
			}
			if b != 0 {
				t.Errorf("record %d: iv[%d] = %d, want 0", n, i, b)
			}
		}
	}
	// The spec's build message carries 8 records (n = 0-7); anything larger must
	// be rejected rather than silently wrapped into the single byte.
	if _, err := StreamIVForRecord(8); err == nil {
		t.Error("record number 8 should be rejected")
	}
}
