package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// XXX: IMPLEMENT THIS
func Test_I2PHMAC(t *testing.T) {
	data := make([]byte, 64)
	for idx := range data {
		data[idx] = 1
	}
	var k HMACKey
	for idx := range k[:] {
		k[idx] = 1
	}
	d := I2PHMAC(data, k)

	// Compute expected SHA256-HMAC result
	mac := hmac.New(sha256.New, k[:])
	mac.Write(data)
	expected := mac.Sum(nil)

	if !bytes.Equal(d[:], expected) {
		t.Logf("%d vs %d", len(d), len(expected))
		t.Logf("%x != %x", d, expected)
		t.Fail()
	}
}
