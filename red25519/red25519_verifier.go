package red25519

import (
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Red25519Verifier checks Red25519 signatures against a public key.
type Red25519Verifier struct {
	k Red25519PublicKey
}

// Verify checks sig against the message data. Red25519 does not pre-hash, so data
// is the message exactly as signed.
func (v *Red25519Verifier) Verify(data, sig []byte) error {
	log.WithFields(logger.Fields{"pkg": "red25519", "func": "Red25519Verifier.Verify", "data_length": len(data), "sig_length": len(sig)}).Debug("Verifying Red25519 signature")
	return v.verify(data, sig)
}

// VerifyHash checks sig with h treated as the message bytes. Red25519 is a
// PureEdDSA-style scheme and does not pre-hash, so this is equivalent to
// [Red25519Verifier.Verify].
func (v *Red25519Verifier) VerifyHash(h, sig []byte) error {
	return v.verify(h, sig)
}

// verify runs the spec's VERIFY: cofactor equation check.
func (v *Red25519Verifier) verify(message, sig []byte) error {
	if len(sig) != SignatureSize {
		return types.ErrBadSignatureSize
	}
	if len(v.k) != PublicKeySize {
		return ErrInvalidPublicKeySize
	}
	vk := v.k.point()
	if vk == nil {
		return oops.Wrapf(ErrInvalidPublicKeySize, "public key is not a valid encoded Edwards point")
	}

	ok, err := verify(vk, message, sig)
	if err != nil {
		return oops.Wrapf(err, "Red25519 VERIFY failed")
	}
	if !ok {
		log.WithFields(logger.Fields{"pkg": "red25519", "func": "Red25519Verifier.verify"}).Warn("Invalid Red25519 signature")
		return types.ErrInvalidSignature
	}
	return nil
}
