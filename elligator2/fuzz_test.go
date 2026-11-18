package elligator2

import (
	"testing"
)

// FuzzElligator2 exercises the Elligator2 encode/decode map used to obfuscate
// Curve25519 public keys on the wire. Decode must accept any 32-byte
// representative without panicking (it masks the two random MSB bits and applies
// the map), and Encode must reject non-representable keys with an error rather
// than panicking. IsRepresentable must agree with Encode's accept/reject
// decision so callers can pre-check safely.
func FuzzElligator2(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Add([]byte("01234567890123456789012345678901"))
	f.Add([]byte("short"))

	f.Fuzz(func(t *testing.T, in []byte) {
		// Decode: any length is handled (wrong length -> error, 32 bytes -> map).
		if _, err := Decode(in); err != nil {
			if len(in) == RepresentativeSize {
				t.Fatalf("Decode failed for valid %d-byte representative: %v", len(in), err)
			}
		}

		// Encode + IsRepresentable must agree on the accept/reject decision.
		_, encErr := Encode(in)
		rep := IsRepresentable(in)
		if rep == (encErr != nil) {
			// rep true but Encode errored, or rep false but Encode succeeded.
			t.Fatalf("IsRepresentable=%v disagrees with Encode err=%v", rep, encErr)
		}

		// Round-trip: when the key is representable, decoding its encoding must
		// yield a 32-byte public key without panicking.
		if encErr == nil {
			enc, _ := Encode(in)
			decoded, err := Decode(enc)
			if err != nil {
				t.Fatalf("Decode of own encoding failed: %v", err)
			}
			if len(decoded) != PublicKeySize {
				t.Fatalf("decoded key length %d, want %d", len(decoded), PublicKeySize)
			}
		}
	})
}
