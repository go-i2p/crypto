package red25519

import (
	"crypto/rand"
	"io"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Red25519Signer produces Red25519 signatures. It is created from a
// [Red25519PrivateKey] via [Red25519PrivateKey.NewSigner].
type Red25519Signer struct {
	k Red25519PrivateKey
	// nonceReader overrides the entropy source for T. It exists so tests can fix
	// T and reproduce the spec's exact signature bytes; production leaves it nil
	// to use crypto/rand.
	nonceReader io.Reader
}

// Sign creates a Red25519 signature over the message data.
//
// Red25519 is a PureEdDSA-style scheme: it signs the message directly (with the
// spec's length prefix applied inside HStar), it does NOT pre-hash. Passing a
// pre-computed digest here signs the digest bytes as the message. This is why
// Sign and SignHash are equivalent for Red25519, matching the types.Signer
// contract.
//
// Every call is randomized: SIGN begins "T = 80 random bytes" and "r = HStar(T,
// vkBytes, m)", so red25519.md §Sign/Verify Calculations notes "Because of the
// random data, every Red25519 signature is different, even when signing the same
// data with the same key." Deterministic signing would break the unlinkability
// that blinded Destinations rely on (see [Red25519PrivateKey]).
//
// Returns [ErrMessageTooLong] if len(data) exceeds [MaxMessageSize] (65534), and
// [ErrInvalidPrivateKeySize] if the key is malformed.
func (s *Red25519Signer) Sign(data []byte) (sig []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "red25519", "func": "Red25519Signer.Sign", "data_length": len(data)}).Debug("Signing data with Red25519")

	if len(s.k) != PrivateKeySize {
		return nil, ErrInvalidPrivateKeySize
	}
	sk, err := s.k.scalar()
	if err != nil {
		return nil, err
	}

	T, err := s.generateT()
	if err != nil {
		return nil, err
	}

	sig, err = sign(sk, data, T)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "red25519", "func": "Red25519Signer.Sign"}).WithError(err).Error("Failed to sign with Red25519")
		return nil, oops.Wrapf(err, "Red25519 SIGN failed")
	}
	return sig, nil
}

// SignHash signs h as the message. Red25519 does not pre-hash, so this is an
// alias for [Red25519Signer.Sign] and the input is treated as message bytes, not
// a digest.
func (s *Red25519Signer) SignHash(h []byte) (sig []byte, err error) {
	return s.Sign(h)
}

// generateT draws the 80-byte random nonce T required by SIGN.
func (s *Red25519Signer) generateT() ([]byte, error) {
	r := s.nonceReader
	if r == nil {
		r = rand.Reader
	}
	T := make([]byte, nonceSizeT)
	if _, err := io.ReadFull(r, T); err != nil {
		return nil, oops.Wrapf(err, "Red25519 SIGN: reading %d random bytes for T failed", nonceSizeT)
	}
	return T, nil
}
