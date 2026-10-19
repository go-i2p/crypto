package ed25519

import (
	"crypto/ed25519"
	"crypto/sha512"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var (
	// ErrInvalidPublicKey indicates the public key is not a valid Ed25519 point
	ErrInvalidPublicKey = oops.Errorf("invalid Ed25519 public key encoding")

	// ErrInvalidScalar indicates the blinding factor is not a valid scalar
	ErrInvalidScalar = oops.Errorf("invalid blinding factor scalar")

	// ErrIdentityPoint indicates the result would be the identity point
	ErrIdentityPoint = oops.Errorf("result is identity point")

	// ErrInvalidPrivateKey indicates the private key is not valid
	ErrInvalidPrivateKey = oops.Errorf("invalid Ed25519 private key")

	// ErrSmallOrderPoint indicates a point that is not in the Ed25519 prime-order
	// subgroup, i.e. it carries a cofactor (order dividing 8) component.
	// encryptedleaseset.md §Goals requires "Blinded public keys must be on the
	// Ed25519 curve and prime-order subgroup".
	ErrSmallOrderPoint = oops.Errorf("point is not in the prime-order subgroup")
)

// applyPublicKeyTransform applies a transformation to a public key using a blinding
// factor, consolidating the shared control flow between blinding and unblinding
// operations that both follow the parse-compute-copy pattern.
func applyPublicKeyTransform(keyBytes, alpha [32]byte, startMsg, endMsg string, compute func([32]byte, [32]byte) (*edwards25519.Point, error)) ([32]byte, error) {
	var result [32]byte
	log.WithFields(logger.Fields{"pkg": "ed25519", "func": "applyPublicKeyTransform"}).Debug(startMsg)
	point, err := compute(keyBytes, alpha)
	if err != nil {
		return result, err
	}
	copy(result[:], point.Bytes())
	log.WithFields(logger.Fields{"pkg": "ed25519", "func": "applyPublicKeyTransform"}).Debug(endMsg)
	return result, nil
}

// BlindPublicKey blinds an Ed25519 public key using a blinding factor (alpha).
// This is used to create unlinkable blinded destinations for EncryptedLeaseSet.
//
// The blinding operation applies: P' = P + [alpha]B where:
//   - P is the original public key point
//   - alpha is the 32-byte blinding factor
//   - B is the Ed25519 base point
//   - P' is the resulting blinded public key
//
// This operation is used in I2P's EncryptedLeaseSet to create per-day blinded
// destinations that cannot be linked to the original destination without knowing alpha.
//
// Parameters:
//   - publicKey: 32-byte Ed25519 public key to blind
//   - alpha: 32-byte blinding factor (typically from kdf.DeriveBlindingFactorI2P)
//
// Returns:
//   - Blinded 32-byte public key
//   - Error if public key is invalid, alpha is invalid, or result is identity
//
// Example:
//
//	// Derive the spec-conformant blinding factor for today
//	alpha, err := kdf.DeriveBlindingFactorI2P(pubKey[:], "", kdf.SigTypeEdDSASha512Ed25519, time.Now())
//	if err != nil {
//	    return err
//	}
//
//	// Blind the public key
//	blindedPubKey, err := ed25519.BlindPublicKey(pubKey, alpha)
//	if err != nil {
//	    return err
//	}
//
// Spec: I2P Proposal 123 - Encrypted LeaseSet
// Reference: https://ed25519.cr.yp.to/papers.html
func BlindPublicKey(publicKey, alpha [32]byte) ([32]byte, error) {
	return applyPublicKeyTransform(
		publicKey, alpha,
		"Blinding Ed25519 public key",
		"Public key blinded successfully",
		func(key, a [32]byte) (*edwards25519.Point, error) {
			P, err := parsePublicKeyPoint(key)
			if err != nil {
				return nil, err
			}
			alphaScalar, err := parseAlphaScalar(a)
			if err != nil {
				return nil, err
			}
			return computeBlindedPoint(P, alphaScalar)
		},
	)
}

// parsePublicKeyPoint parses a public key as an edwards25519 point.
func parsePublicKeyPoint(publicKey [32]byte) (*edwards25519.Point, error) {
	P, err := (&edwards25519.Point{}).SetBytes(publicKey[:])
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "ed25519", "func": "parsePublicKeyPoint", "error": err}).Error("Failed to parse public key")
		return nil, oops.Wrapf(ErrInvalidPublicKey, "failed to parse public key: %v", err)
	}
	return P, nil
}

// parseAlphaScalar parses a blinding factor as an edwards25519 scalar.
func parseAlphaScalar(alpha [32]byte) (*edwards25519.Scalar, error) {
	alphaScalar, err := (&edwards25519.Scalar{}).SetCanonicalBytes(alpha[:])
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "ed25519", "func": "parseAlphaScalar", "error": err}).Error("Failed to parse blinding factor as scalar")
		return nil, oops.Wrapf(ErrInvalidScalar, "failed to parse alpha: %v", err)
	}
	return alphaScalar, nil
}

// computeBlindedPoint computes P' = P + [alpha]B and validates the result.
func computeBlindedPoint(P *edwards25519.Point, alphaScalar *edwards25519.Scalar) (*edwards25519.Point, error) {
	// Reject a small-order input point. encryptedleaseset.md §Goals requires
	// "Blinded public keys must be on the Ed25519 curve and prime-order subgroup".
	// [alpha]B is always in the prime-order subgroup, so P' inherits any torsion
	// component of P: if P has order dividing 8 (a nontrivial small-order point),
	// P' has order 8L and is off the subgroup. Point.SetBytes accepts such points
	// (they are on the curve), so parsing alone does not catch them.
	if !isInPrimeOrderSubgroup(P) {
		log.WithFields(logger.Fields{"pkg": "ed25519", "func": "computeBlindedPoint"}).Error("Input public key is not in the prime-order subgroup")
		return nil, ErrSmallOrderPoint
	}

	alphaB := (&edwards25519.Point{}).ScalarBaseMult(alphaScalar)
	blindedPoint := (&edwards25519.Point{}).Add(P, alphaB)

	identityPoint := edwards25519.NewIdentityPoint()
	if blindedPoint.Equal(identityPoint) == 1 {
		log.WithFields(logger.Fields{"pkg": "ed25519", "func": "computeBlindedPoint"}).Error("Blinded public key is identity point")
		return nil, ErrIdentityPoint
	}

	// The result is in the subgroup iff P was, but re-checking is cheap insurance
	// against a future change to the transform.
	if !isInPrimeOrderSubgroup(blindedPoint) {
		return nil, ErrSmallOrderPoint
	}

	return blindedPoint, nil
}

// BlindPrivateKey blinds an Ed25519 private key using a blinding factor (alpha).
// The blinded private key can sign on behalf of the blinded public key.
//
// The blinding operation applies: d' = d + alpha (mod L) where:
//   - d is the original private scalar (derived from the private key seed)
//   - alpha is the 32-byte blinding factor
//   - L is the Ed25519 group order
//   - d' is the resulting blinded private scalar
//
// The returned blinded private key is a 64-byte value with the format:
//   - [32 bytes: blinded scalar d']
//   - [32 bytes: blinded public key P']
//
// IMPORTANT: The returned key cannot be used directly with crypto/ed25519.Sign()
// because Go's ed25519 expects [seed][pubkey] format, not [scalar][pubkey].
// To sign with a blinded key, you must use the scalar directly with edwards25519:
//
//	scalar, _ := (&edwards25519.Scalar{}).SetCanonicalBytes(blindedPriv[:32])
//	// Use scalar for signing with edwards25519 API
//
// Parameters:
//   - privateKey: 64-byte Ed25519 private key to blind
//   - alpha: 32-byte blinding factor (same alpha used for BlindPublicKey)
//
// Returns:
//   - Blinded 64-byte value [scalar][pubkey]
//   - Error if private key is invalid or alpha is invalid
//
// Example:
//
//	// Blind both private and public keys with the same spec-conformant alpha
//	alpha, _ := kdf.DeriveBlindingFactorI2P(pubKey[:], "", kdf.SigTypeEdDSASha512Ed25519, time.Now())
//	blindedPriv, _ := ed25519.BlindPrivateKey(privKey, alpha)
//	blindedPub, _ := ed25519.BlindPublicKey(pubKey, alpha)
//
//	// Extract scalar for signing (requires edwards25519 library)
//	scalar, _ := (&edwards25519.Scalar{}).SetCanonicalBytes(blindedPriv[:32])
//
// Spec: I2P Proposal 123 - Encrypted LeaseSet
func BlindPrivateKey(privateKey [64]byte, alpha [32]byte) ([64]byte, error) {
	var result [64]byte

	log.WithFields(logger.Fields{"pkg": "ed25519", "func": "BlindPrivateKey"}).Debug("Blinding Ed25519 private key")

	if len(privateKey) != ed25519.PrivateKeySize {
		return result, oops.Wrapf(ErrInvalidPrivateKey, "expected %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	d, err := deriveScalarFromSeed(privateKey[:32])
	if err != nil {
		return result, err
	}

	blindedScalar, err := computeBlindedScalar(d, alpha)
	if err != nil {
		return result, err
	}

	result = constructBlindedPrivateKey(blindedScalar)

	log.WithFields(logger.Fields{"pkg": "ed25519", "func": "BlindPrivateKey"}).Debug("Private key blinded successfully")

	return result, nil
}

// deriveScalarFromSeed derives the Ed25519 private scalar from a 32-byte seed.
func deriveScalarFromSeed(seed []byte) (*edwards25519.Scalar, error) {
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64

	d, err := (&edwards25519.Scalar{}).SetBytesWithClamping(h[:32])
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "ed25519", "func": "deriveScalarFromSeed", "error": err}).Error("Failed to parse private scalar")
		return nil, oops.Wrapf(ErrInvalidPrivateKey, "failed to parse private scalar: %v", err)
	}

	return d, nil
}

// computeBlindedScalar computes the blinded scalar d' = d + alpha (mod L).
func computeBlindedScalar(d *edwards25519.Scalar, alpha [32]byte) (*edwards25519.Scalar, error) {
	alphaScalar, err := (&edwards25519.Scalar{}).SetCanonicalBytes(alpha[:])
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "ed25519", "func": "computeBlindedScalar", "error": err}).Error("Failed to parse blinding factor")
		return nil, oops.Wrapf(ErrInvalidScalar, "failed to parse alpha: %v", err)
	}

	blindedScalar := (&edwards25519.Scalar{}).Add(d, alphaScalar)
	return blindedScalar, nil
}

// constructBlindedPrivateKey constructs the blinded private key in [scalar][pubkey] format.
func constructBlindedPrivateKey(blindedScalar *edwards25519.Scalar) [64]byte {
	var result [64]byte

	blindedPubPoint := (&edwards25519.Point{}).ScalarBaseMult(blindedScalar)

	copy(result[:32], blindedScalar.Bytes())
	copy(result[32:], blindedPubPoint.Bytes())

	return result
}

// UnblindPublicKey reverses the blinding operation on a public key.
// This is useful for verification: given P' and alpha, recover P.
//
// The operation applies: P = P' - [alpha]B where:
//   - P' is the blinded public key
//   - alpha is the blinding factor used to create P'
//   - B is the Ed25519 base point
//   - P is the original public key
//
// This is primarily used for testing and verification. In normal operation,
// clients derive blinded keys independently rather than unblinding them.
//
// Parameters:
//   - blindedPublicKey: 32-byte blinded Ed25519 public key
//   - alpha: 32-byte blinding factor that was used to blind the key
//
// Returns:
//   - Original unblinded 32-byte public key
//   - Error if inputs are invalid or result is identity
//
// Example:
//
//	// Verify blinding/unblinding round-trip
//	alpha, _ := kdf.DeriveBlindingFactorI2P(original[:], "", kdf.SigTypeEdDSASha512Ed25519, time.Now())
//	blinded, _ := ed25519.BlindPublicKey(original, alpha)
//	recovered, _ := ed25519.UnblindPublicKey(blinded, alpha)
//	// recovered should equal original
func UnblindPublicKey(blindedPublicKey, alpha [32]byte) ([32]byte, error) {
	return applyPublicKeyTransform(
		blindedPublicKey, alpha,
		"Unblinding Ed25519 public key",
		"Public key unblinded successfully",
		func(key, a [32]byte) (*edwards25519.Point, error) {
			Pblinded, err := parseBlindedPublicKey(key)
			if err != nil {
				return nil, err
			}
			alphaB, err := computeAlphaBasePoint(a)
			if err != nil {
				return nil, err
			}
			return subtractAndValidate(Pblinded, alphaB)
		},
	)
}

// parseBlindedPublicKey parses a blinded public key as an edwards25519 point.
func parseBlindedPublicKey(blindedPublicKey [32]byte) (*edwards25519.Point, error) {
	Pblinded, err := (&edwards25519.Point{}).SetBytes(blindedPublicKey[:])
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "ed25519", "func": "parseBlindedPublicKey", "error": err}).Error("Failed to parse blinded public key")
		return nil, oops.Wrapf(ErrInvalidPublicKey, "failed to parse blinded public key: %v", err)
	}
	return Pblinded, nil
}

// computeAlphaBasePoint computes [alpha]B for unblinding operations.
func computeAlphaBasePoint(alpha [32]byte) (*edwards25519.Point, error) {
	alphaScalar, err := (&edwards25519.Scalar{}).SetCanonicalBytes(alpha[:])
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "ed25519", "func": "computeAlphaBasePoint", "error": err}).Error("Failed to parse blinding factor")
		return nil, oops.Wrapf(ErrInvalidScalar, "failed to parse alpha: %v", err)
	}

	alphaB := (&edwards25519.Point{}).ScalarBaseMult(alphaScalar)
	return alphaB, nil
}

// subtractAndValidate performs P' - [alpha]B and validates the result isn't identity.
func subtractAndValidate(Pblinded, alphaB *edwards25519.Point) (*edwards25519.Point, error) {
	original := (&edwards25519.Point{}).Subtract(Pblinded, alphaB)

	identityPoint := edwards25519.NewIdentityPoint()
	if original.Equal(identityPoint) == 1 {
		log.WithFields(logger.Fields{"pkg": "ed25519", "func": "subtractAndValidate"}).Error("Unblinded public key is identity point")
		return nil, ErrIdentityPoint
	}

	return original, nil
}

// orderL is the Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
// (red25519.md §Definitions), as a big.Int so it can be used as a plain integer
// multiplier. edwards25519.Scalar is reduced mod L, so [L] cannot be expressed as
// a Scalar; [L]P must be computed by double-and-add over the integer.
var orderL = func() *big.Int {
	l := new(big.Int).Lsh(big.NewInt(1), 252)
	add, ok := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	if !ok {
		panic("ed25519: invalid order constant")
	}
	return l.Add(l, add)
}()

// mulByOrderL computes [L]P by double-and-add over the integer L.
func mulByOrderL(P *edwards25519.Point) *edwards25519.Point {
	acc := edwards25519.NewIdentityPoint()
	cur := new(edwards25519.Point).Set(P)
	for i := 0; i < orderL.BitLen(); i++ {
		if orderL.Bit(i) == 1 {
			acc.Add(acc, cur)
		}
		cur.Double(cur)
	}
	return acc
}

// isInPrimeOrderSubgroup reports whether P lies in the order-L prime-order
// subgroup, i.e. [L]P is the identity. The full group has order 8L, so a point
// with a small-order (cofactor) component fails this test.
//
// This enforces encryptedleaseset.md §Goals: "Blinded public keys must be on the
// Ed25519 curve and prime-order subgroup". Point.SetBytes accepts torsion points
// (they are on the curve), so parsing alone is not enough: a small-order input A
// yields A' = A + [alpha]B of order 8L, off the subgroup, and because L is odd
// the torsion component survives the [L] test ([L]A' = [L]A != identity).
func isInPrimeOrderSubgroup(P *edwards25519.Point) bool {
	return mulByOrderL(P).Equal(edwards25519.NewIdentityPoint()) == 1
}
