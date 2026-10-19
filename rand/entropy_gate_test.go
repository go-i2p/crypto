package rand

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// failingReader is an entropy source that always errors, used to exercise the
// failure paths without depending on a broken OS CSPRNG.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy source is dead") }

// constantReader returns fixed bytes: a source that trips the heuristic entropy
// check (zero entropy, one distinct byte) but is otherwise a healthy read.
type constantReader struct{ b byte }

func (c constantReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.b
	}
	return len(p), nil
}

// TestSecureReaderAdvisoryGateNeverRejects pins F-15: a read that trips the
// heuristic entropy check must be returned unchanged, not retried and not turned
// into an error. No I2P spec asks for entropy validation of a CSPRNG, and the OS
// CSPRNG is the authority on its own output; the old retry-then-fail loop
// converted good reads into spurious failures.
func TestSecureReaderAdvisoryGateNeverRejects(t *testing.T) {
	sr := &SecureReader{source: constantReader{b: 0xAB}}

	// 32+ bytes is the size that triggers the check. All-equal bytes give
	// Shannon entropy 0 and len(frequency) == 1, so validateEntropy is false.
	buf := make([]byte, 64)
	n, err := sr.Read(buf)
	if err != nil {
		t.Fatalf("Read failed the advisory gate: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("Read returned %d bytes, want %d", n, len(buf))
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{0xAB}, len(buf))) {
		t.Error("Read altered or discarded the source output")
	}
	// Confirm the check really does fail on this input, otherwise the test above
	// proves nothing.
	if sr.validateEntropy(buf) {
		t.Error("validateEntropy accepted a constant buffer; the test input is not exercising the gate")
	}
}

// TestSecureReaderPropagatesSourceError verifies the gate does not mask a genuine
// CSPRNG failure.
func TestSecureReaderPropagatesSourceError(t *testing.T) {
	sr := &SecureReader{source: failingReader{}}
	if _, err := sr.Read(make([]byte, 32)); err == nil {
		t.Error("Read succeeded against a failing source; the error must propagate")
	}
}

// TestCryptoSourceErrVariantsReturnError pins the first half of F-16's
// remediation: the error-reporting API surfaces a dead CSPRNG instead of
// substituting a constant.
func TestCryptoSourceErrVariantsReturnError(t *testing.T) {
	// Both the primary reader and the DefaultSecureReader fallback must fail.
	// DefaultSecureReader reads from crypto/rand, which cannot be made to fail
	// here, so exercise the primary path against a source that errors while the
	// fallback is stubbed out.
	saved := DefaultSecureReader
	defer func() { DefaultSecureReader = saved }()
	DefaultSecureReader = &SecureReader{source: failingReader{}}

	c := &cryptoSource{reader: failingReader{}}

	if n, err := c.Int63Err(); err == nil {
		t.Errorf("Int63Err returned %d with no error against a dead source", n)
	} else if n != 0 {
		t.Errorf("Int63Err returned %d on failure, want 0", n)
	}

	if n, err := c.Uint64Err(); err == nil {
		t.Errorf("Uint64Err returned %d with no error against a dead source", n)
	} else if n != 0 {
		t.Errorf("Uint64Err returned %d on failure, want 0", n)
	}
}

// TestCryptoSourcePanicsInsteadOfConstant pins the second half of F-16: the
// math/rand-compatible API used to return the constant 1 when both entropy
// sources failed, silently handing callers fixed key material. It must panic
// instead, so no caller can build a key from a constant.
func TestCryptoSourcePanicsInsteadOfConstant(t *testing.T) {
	saved := DefaultSecureReader
	defer func() { DefaultSecureReader = saved }()
	DefaultSecureReader = &SecureReader{source: failingReader{}}

	c := &cryptoSource{reader: failingReader{}}

	for _, name := range []string{"Int63", "Uint64"} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("%s returned normally against a dead CSPRNG; it must not return a constant", name)
				}
				if v, ok := r.(int64); ok && v == 1 {
					t.Errorf("%s panicked with the old constant value", name)
				}
			}()
			if name == "Int63" {
				_ = c.Int63()
			} else {
				_ = c.Uint64()
			}
		})
	}
}

// TestRandErrorVariantsRoundTrip checks the error-returning helpers work against
// a healthy source and that the global wrappers agree with the method forms.
func TestRandErrorVariantsRoundTrip(t *testing.T) {
	r := New(NewSource(0))
	n, err := r.Int63Err()
	if err != nil {
		t.Fatalf("Int63Err on a healthy source: %v", err)
	}
	if n < 0 {
		t.Errorf("Int63Err returned a negative value: %d", n)
	}
	if _, err := r.Uint64Err(); err != nil {
		t.Fatalf("Uint64Err on a healthy source: %v", err)
	}
	if _, err := Int63Err(); err != nil {
		t.Fatalf("package Int63Err: %v", err)
	}
	if _, err := Uint64Err(); err != nil {
		t.Fatalf("package Uint64Err: %v", err)
	}
}

// TestErrorSourceSatisfied is a compile-time guard that the CSPRNG source exposes
// both interfaces, so the error channel cannot silently disappear.
func TestErrorSourceSatisfied(t *testing.T) {
	var src any = &cryptoSource{reader: io.Reader(nil)}
	if _, ok := src.(Source64); !ok {
		t.Error("cryptoSource no longer satisfies Source64")
	}
	if _, ok := src.(ErrorSource); !ok {
		t.Error("cryptoSource no longer satisfies ErrorSource")
	}
}
