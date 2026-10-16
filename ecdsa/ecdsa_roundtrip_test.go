package ecdsa

// Regression tests for the sign/verify round trip through the package's own
// typed keys. I2P common structures serialize ECDSA signing public keys as the
// raw big-endian X||Y concatenation (64/96/132 bytes for P-256/P-384/P-521)
// with no SEC1 0x04 uncompressed-point prefix, so NewVerifier must accept that
// encoding. See https://i2p.net/en/docs/specs/cryptography/.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/go-i2p/crypto/types"
)

// scalarFor returns a valid, curve-ordered private scalar padded to the
// curve's coordinate size.
func scalarFor(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	size := (curve.Params().BitSize + 7) / 8
	out := make([]byte, size)
	d := key.D.Bytes()
	copy(out[size-len(d):], d)
	return out
}

func TestECDSARoundTrip(t *testing.T) {
	data := []byte("message to sign and verify")

	t.Run("P256", func(t *testing.T) {
		priv, err := NewECP256PrivateKey(scalarFor(t, elliptic.P256()))
		if err != nil {
			t.Fatalf("NewECP256PrivateKey: %v", err)
		}
		assertRoundTrip(t, priv, data)
	})

	t.Run("P384", func(t *testing.T) {
		priv, err := NewECP384PrivateKey(scalarFor(t, elliptic.P384()))
		if err != nil {
			t.Fatalf("NewECP384PrivateKey: %v", err)
		}
		assertRoundTrip(t, priv, data)
	})

	t.Run("P521", func(t *testing.T) {
		priv, err := NewECP521PrivateKey(scalarFor(t, elliptic.P521()))
		if err != nil {
			t.Fatalf("NewECP521PrivateKey: %v", err)
		}
		assertRoundTrip(t, priv, data)
	})
}

// assertRoundTrip signs with the typed private key, derives its public key,
// builds a verifier from that public key, and verifies the signature. This is
// the path the package documentation advertises, and it previously failed
// because NewVerifier used elliptic.Unmarshal, which rejects the I2P X||Y form.
func assertRoundTrip(t *testing.T, priv types.SigningPrivateKey, data []byte) {
	t.Helper()

	signer, err := priv.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	verifier, err := pub.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier on a public key produced by this package: %v", err)
	}
	if err := verifier.Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
