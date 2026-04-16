package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

type ECDSAVerifier struct {
	k *ecdsa.PublicKey
	c elliptic.Curve
	h crypto.Hash
}

// verify a signature given the hash
func (v *ECDSAVerifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logger.Fields{
		"pkg":         "ecdsa",
		"func":        "ECDSAVerifier.VerifyHash",
		"hash_length": len(h),
		"sig_length":  len(sig),
	}).Debug("Verifying ECDSA signature hash")

	// Calculate expected signature length based on curve
	curveOrderBytes := (v.c.Params().BitSize + 7) / 8
	expectedSigLen := 2 * curveOrderBytes

	if len(sig) != expectedSigLen {
		log.WithFields(logger.Fields{
			"pkg":             "ecdsa",
			"func":            "ECDSAVerifier.VerifyHash",
			"expected_length": expectedSigLen,
			"actual_length":   len(sig),
		}).Error("Unsupported ECDSA signature format or length")
		err = oops.Errorf("unsupported ECDSA signature format: got %d bytes, expected %d (R||S)", len(sig), expectedSigLen)
		return err
	}

	// Parse r and s from signature bytes
	r := new(big.Int).SetBytes(sig[:curveOrderBytes])
	s := new(big.Int).SetBytes(sig[curveOrderBytes:])

	if !ecdsa.Verify(v.k, h, r, s) {
		log.WithFields(logger.Fields{"pkg": "ecdsa", "func": "ECDSAVerifier.VerifyHash"}).Warn("Invalid ECDSA signature")
		err = types.ErrInvalidSignature
	} else {
		log.WithFields(logger.Fields{"pkg": "ecdsa", "func": "ECDSAVerifier.VerifyHash"}).Debug("ECDSA signature verified successfully")
	}
	return err
}

// verify a block of data by hashing it and comparing the hash against the signature
func (v *ECDSAVerifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logger.Fields{
		"pkg":         "ecdsa",
		"func":        "ECDSAVerifier.Verify",
		"data_length": len(data),
		"sig_length":  len(sig),
	}).Debug("Verifying ECDSA signature")
	// hash the data
	hasher := v.h.New()
	hasher.Write(data)
	h := hasher.Sum(nil)
	// verify
	err = v.VerifyHash(h, sig)
	return err
}

func CreateECVerifier(c elliptic.Curve, h crypto.Hash, k []byte) (ev *ECDSAVerifier, err error) {
	log.WithFields(logger.Fields{
		"pkg":   "ecdsa",
		"func":  "CreateECVerifier",
		"curve": c.Params().Name,
		"hash":  h.String(),
	}).Debug("Creating ECDSA verifier")
	x, y := elliptic.Unmarshal(c, k[:])
	if x == nil {
		log.WithFields(logger.Fields{"pkg": "ecdsa", "func": "CreateECVerifier"}).Error("Invalid ECDSA key format")
		err = types.ErrInvalidKeyFormat
	} else {
		ev = &ECDSAVerifier{
			c: c,
			h: h,
		}
		ev.k = &ecdsa.PublicKey{c, x, y}
		log.WithFields(logger.Fields{"pkg": "ecdsa", "func": "CreateECVerifier"}).Debug("ECDSA verifier created successfully")
	}
	return ev, err
}
