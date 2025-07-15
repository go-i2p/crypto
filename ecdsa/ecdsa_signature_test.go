package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// TestSignatureFormatFix validates that the VerifyHash method correctly parses ECDSA signatures
func TestSignatureFormatFix(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a test key pair using standard library
			privateKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Marshall the public key
			pubKeyBytes := elliptic.Marshal(tc.curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)

			// Create our verifier
			verifier, err := CreateECVerifier(tc.curve, crypto.SHA256, pubKeyBytes)
			if err != nil {
				t.Fatalf("Failed to create verifier: %v", err)
			}

			// Test data
			data := []byte("test message for signing")

			// Sign with standard library
			hasher := sha256.New()
			hasher.Write(data)
			hash := hasher.Sum(nil)

			r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}

			// Create signature in the format our verifier expects
			curveOrderBytes := (tc.curve.Params().BitSize + 7) / 8
			signature := make([]byte, 2*curveOrderBytes)

			rBytes := r.Bytes()
			sBytes := s.Bytes()

			// Pad with zeros if needed and copy to signature
			copy(signature[curveOrderBytes-len(rBytes):curveOrderBytes], rBytes)
			copy(signature[2*curveOrderBytes-len(sBytes):], sBytes)

			// Test verification with hash
			err = verifier.VerifyHash(hash, signature)
			if err != nil {
				t.Errorf("VerifyHash failed for %s: %v", tc.name, err)
			} else {
				t.Logf("✅ VerifyHash successful for %s", tc.name)
			}

			// Test verification with data
			err = verifier.Verify(data, signature)
			if err != nil {
				t.Errorf("Verify failed for %s: %v", tc.name, err)
			} else {
				t.Logf("✅ Verify successful for %s", tc.name)
			}
		})
	}
}
