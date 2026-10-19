package red25519

import (
	"crypto/rand"
	"io"

	"github.com/go-i2p/crypto/common"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// GenerateRed25519Key runs GENERATE_PRIVATE: "s = 64 random bytes; return s mod
// L". The result is a uniformly random scalar mod L, which red25519.md
// §Security implications requires so that re-randomized keys are "identically
// distributed" to freshly generated ones.
func GenerateRed25519Key() (types.SigningPrivateKey, error) {
	return generateRed25519Key(rand.Reader)
}

// GenerateRed25519KeyWith generates a key from an explicit entropy source. A nil
// reader selects crypto/rand.
func GenerateRed25519KeyWith(r io.Reader) (types.SigningPrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	return generateRed25519Key(r)
}

func generateRed25519Key(r io.Reader) (types.SigningPrivateKey, error) {
	s, err := generatePrivate(r)
	if err != nil {
		return nil, oops.Wrapf(err, "GENERATE_PRIVATE failed")
	}
	return Red25519PrivateKey(encodeScalarLE(s)), nil
}

// GenerateRed25519KeyPair generates a Red25519 key pair. This is the recommended
// API, returning concrete types without interface conversions.
//
// The private key is DERIVE_PUBLIC-consistent with the public key by
// construction: public = [sk] B.
//
// Example:
//
//	pubKey, privKey, err := red25519.GenerateRed25519KeyPair()
//	if err != nil {
//		return err
//	}
//	defer privKey.Zero()
func GenerateRed25519KeyPair() (*Red25519PublicKey, *Red25519PrivateKey, error) {
	pubRaw, privRaw, err := common.GenerateKeyPair("Red25519", func() ([]byte, []byte, error) {
		s, err := generatePrivate(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		priv := encodeScalarLE(s)
		pub := encodePoint(derivePublic(s))
		return pub, priv, nil
	}, log)
	if err != nil {
		return nil, nil, err
	}

	pubKey := Red25519PublicKey(pubRaw)
	privKey := Red25519PrivateKey(privRaw)
	return &pubKey, &privKey, nil
}
