package ed25519

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
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
)

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
//   - alpha: 32-byte blinding factor (typically from kdf.DeriveBlindingFactor)
//
// Returns:
//   - Blinded 32-byte public key
//   - Error if public key is invalid, alpha is invalid, or result is identity
//
// Example:
//
//	// Derive blinding factor for today
//	alpha, _ := kdf.DeriveBlindingFactor(secret, "2025-11-24")
//
//	// Blind the public key
//	blindedPubKey, err := ed25519.BlindPublicKey(pubKey, alpha)
//	if err != nil {
//	    return err
//	}
//
// Spec: I2P Proposal 123 - Encrypted LeaseSet
// Reference: https://ed25519.cr.yp.to/papers.html
func BlindPublicKey(publicKey [32]byte, alpha [32]byte) ([32]byte, error) {
	var result [32]byte

	log.Debug("Blinding Ed25519 public key")

	P, err := parsePublicKeyPoint(publicKey)
	if err != nil {
		return result, err
	}

	alphaScalar, err := parseAlphaScalar(alpha)
	if err != nil {
		return result, err
	}

	blindedPoint, err := computeBlindedPoint(P, alphaScalar)
	if err != nil {
		return result, err
	}

	copy(result[:], blindedPoint.Bytes())

	log.Debug("Public key blinded successfully")

	return result, nil
}

// parsePublicKeyPoint parses a public key as an edwards25519 point.
func parsePublicKeyPoint(publicKey [32]byte) (*edwards25519.Point, error) {
	P, err := (&edwards25519.Point{}).SetBytes(publicKey[:])
	if err != nil {
		log.WithField("error", err).Error("Failed to parse public key")
		return nil, oops.Wrapf(ErrInvalidPublicKey, "failed to parse public key: %v", err)
	}
	return P, nil
}

// parseAlphaScalar parses a blinding factor as an edwards25519 scalar.
func parseAlphaScalar(alpha [32]byte) (*edwards25519.Scalar, error) {
	alphaScalar, err := (&edwards25519.Scalar{}).SetCanonicalBytes(alpha[:])
	if err != nil {
		log.WithField("error", err).Error("Failed to parse blinding factor as scalar")
		return nil, oops.Wrapf(ErrInvalidScalar, "failed to parse alpha: %v", err)
	}
	return alphaScalar, nil
}

// computeBlindedPoint computes P' = P + [alpha]B and validates the result.
func computeBlindedPoint(P *edwards25519.Point, alphaScalar *edwards25519.Scalar) (*edwards25519.Point, error) {
	alphaB := (&edwards25519.Point{}).ScalarBaseMult(alphaScalar)
	blindedPoint := (&edwards25519.Point{}).Add(P, alphaB)

	identityPoint := edwards25519.NewIdentityPoint()
	if blindedPoint.Equal(identityPoint) == 1 {
		log.Error("Blinded public key is identity point")
		return nil, ErrIdentityPoint
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
//	// Blind both private and public keys with same alpha
//	alpha, _ := kdf.DeriveBlindingFactor(secret, "2025-11-24")
//	blindedPriv, _ := ed25519.BlindPrivateKey(privKey, alpha)
//	blindedPub, _ := ed25519.BlindPublicKey(pubKey, alpha)
//
//	// Extract scalar for signing (requires edwards25519 library)
//	scalar, _ := (&edwards25519.Scalar{}).SetCanonicalBytes(blindedPriv[:32])
//
// Spec: I2P Proposal 123 - Encrypted LeaseSet
func BlindPrivateKey(privateKey [64]byte, alpha [32]byte) ([64]byte, error) {
	var result [64]byte

	log.Debug("Blinding Ed25519 private key")

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

	log.Debug("Private key blinded successfully")

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
		log.WithField("error", err).Error("Failed to parse private scalar")
		return nil, oops.Wrapf(ErrInvalidPrivateKey, "failed to parse private scalar: %v", err)
	}

	return d, nil
}

// computeBlindedScalar computes the blinded scalar d' = d + alpha (mod L).
func computeBlindedScalar(d *edwards25519.Scalar, alpha [32]byte) (*edwards25519.Scalar, error) {
	alphaScalar, err := (&edwards25519.Scalar{}).SetCanonicalBytes(alpha[:])
	if err != nil {
		log.WithField("error", err).Error("Failed to parse blinding factor")
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
//	alpha, _ := kdf.DeriveBlindingFactor(secret, "2025-11-24")
//	blinded, _ := ed25519.BlindPublicKey(original, alpha)
//	recovered, _ := ed25519.UnblindPublicKey(blinded, alpha)
//	// recovered should equal original
func UnblindPublicKey(blindedPublicKey [32]byte, alpha [32]byte) ([32]byte, error) {
	var result [32]byte

	log.Debug("Unblinding Ed25519 public key")

	Pblinded, err := parseBlindedPublicKey(blindedPublicKey)
	if err != nil {
		return result, err
	}

	alphaB, err := computeAlphaBasePoint(alpha)
	if err != nil {
		return result, err
	}

	original, err := subtractAndValidate(Pblinded, alphaB)
	if err != nil {
		return result, err
	}

	copy(result[:], original.Bytes())

	log.Debug("Public key unblinded successfully")

	return result, nil
}

// parseBlindedPublicKey parses a blinded public key as an edwards25519 point.
func parseBlindedPublicKey(blindedPublicKey [32]byte) (*edwards25519.Point, error) {
	Pblinded, err := (&edwards25519.Point{}).SetBytes(blindedPublicKey[:])
	if err != nil {
		log.WithField("error", err).Error("Failed to parse blinded public key")
		return nil, oops.Wrapf(ErrInvalidPublicKey, "failed to parse blinded public key: %v", err)
	}
	return Pblinded, nil
}

// computeAlphaBasePoint computes [alpha]B for unblinding operations.
func computeAlphaBasePoint(alpha [32]byte) (*edwards25519.Point, error) {
	alphaScalar, err := (&edwards25519.Scalar{}).SetCanonicalBytes(alpha[:])
	if err != nil {
		log.WithField("error", err).Error("Failed to parse blinding factor")
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
		log.Error("Unblinded public key is identity point")
		return nil, ErrIdentityPoint
	}

	return original, nil
}
