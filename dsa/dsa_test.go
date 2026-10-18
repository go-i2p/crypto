package dsa

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/go-i2p/crypto/types"
)

func TestDSA(t *testing.T) {
	var sk DSAPrivateKey
	var pk types.SigningPublicKey
	var err error
	generatedKey, err := sk.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sk = generatedKey.(DSAPrivateKey)
	if err == nil {
		zeros := 0
		for b := range sk {
			if b == 0 {
				zeros++
			}
		}
		if zeros == len(sk) {
			t.Logf("key generation yielded all zeros")
			t.Fail()
		}
		pk, err = sk.Public()
		if err != nil {
			t.Fatal(err)
		}
		data := make([]byte, 512)
		io.ReadFull(rand.Reader, data)
		if err == nil {
			var sig []byte
			var signer types.Signer
			signer, err = sk.NewSigner()
			if err == nil {
				sig, err = signer.Sign(data)
				if err == nil {
					t.Logf("sig=%q", sig)
					var verify types.Verifier
					verify, err = pk.NewVerifier()
					if err == nil {
						err = verify.Verify(data, sig)
					}
				}
			}
		}
	}
	if err != nil {
		t.Logf("failed: %s", err.Error())
		t.Fail()
	}
}

func BenchmarkDSAGenerate(b *testing.B) {
	var sk DSAPrivateKey
	for n := 0; n < b.N; n++ {
		_, err := sk.Generate()
		if err != nil {
			panic(err.Error())
		}
	}
}

func BenchmarkDSASignVerify(b *testing.B) {
	var sk DSAPrivateKey
	var pk types.SigningPublicKey
	var err error
	generatedKey, err := sk.Generate()
	if err != nil {
		panic(err.Error())
	}
	sk = generatedKey.(DSAPrivateKey)
	pk, err = sk.Public()
	if err != nil {
		panic(err.Error())
	}
	s, _ := sk.NewSigner()
	v, _ := pk.NewVerifier()
	data := make([]byte, 1024)
	fail := 0
	for n := 0; n < b.N; n++ {
		sig, err := s.Sign(data)
		if err != nil {
			panic(err.Error())
		}
		err = v.Verify(data, sig)
		if err != nil {
			fail++
		}
	}
	log.Debugf("%d fails %d signs", fail, b.N)
}

// TestDSAPublicKeyRightAligned is a deterministic regression test for the
// big-endian alignment of derived DSA public keys. With this private exponent X,
// Y = g^X mod p has a leading zero byte, so Y.Bytes() is only 127 bytes. Copying
// it to the start of the 128-byte array (left-aligning) shifts every byte and
// yields a key that fails to verify its own signatures.
func TestDSAPublicKeyRightAligned(t *testing.T) {
	xHex := "5cfa90db96ef1e78cba25e108326180b7c212a70"
	wantY := "0053996577f6fb97bba787b38e8d7353f831560faede54fc" +
		"5a1c87e3e2969fe5924ccafa2acf00700d415503fae23869" +
		"1245b5701da625eed6266b85affb251b826a5f4562e32c4e" +
		"b2de13e0d290c1bd2d5b4b60f254dafecf8dd68580c4d9df" +
		"53a674433f0ddc30f0411b9d98d17cecaf4ef1f65b52cb0a" +
		"1131029ca93b4012"

	xb, err := hex.DecodeString(xHex)
	if err != nil {
		t.Fatalf("bad test vector: %v", err)
	}
	var k DSAPrivateKey
	copy(k[len(k)-len(xb):], xb)

	pub, err := k.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}
	have := hex.EncodeToString(pub.Bytes())
	if have != wantY {
		t.Errorf("DSA public key not right-aligned:\n got %s\nwant %s", have, wantY)
	}

	// The derived key must verify a signature from the same private key.
	signer, err := k.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	msg := []byte("i2p dsa alignment regression")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ver, err := pub.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := ver.Verify(msg, sig); err != nil {
		t.Errorf("self-round-trip verify failed: %v", err)
	}
}
