package chacha20

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/go-i2p/crypto/types"
)

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "successful key generation",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if key == nil {
					t.Error("GenerateKey() returned nil key")
				}
				if key.Len() != KeySize {
					t.Errorf("GenerateKey() key length = %d, want %d", key.Len(), KeySize)
				}
				// Verify key is not all zeros
				allZeros := true
				for _, b := range key.Bytes() {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Error("GenerateKey() returned all-zero key")
				}
			}
		})
	}
}

func TestChaCha20Key_Len(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if got := key.Len(); got != KeySize {
		t.Errorf("ChaCha20Key.Len() = %v, want %v", got, KeySize)
	}
}

func TestChaCha20Key_Bytes(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	bytes := key.Bytes()
	if len(bytes) != KeySize {
		t.Errorf("ChaCha20Key.Bytes() length = %v, want %v", len(bytes), KeySize)
	}

	// Verify it's a copy, not the original
	original := key.Bytes()
	copy := key.Bytes()
	copy[0] = ^copy[0] // Flip bits
	if bytes[0] != original[0] {
		t.Error("ChaCha20Key.Bytes() should return a copy")
	}
}

func TestChaCha20Key_NewEncrypter(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypter, err := key.NewEncrypter()
	if err != nil {
		t.Errorf("ChaCha20Key.NewEncrypter() error = %v", err)
		return
	}

	if encrypter == nil {
		t.Error("ChaCha20Key.NewEncrypter() returned nil encrypter")
	}

	// Verify it implements the Encrypter interface
	var _ types.Encrypter = encrypter
}

func TestChaCha20Key_NewDecrypter(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	decrypter, err := key.NewDecrypter()
	if err != nil {
		t.Errorf("ChaCha20Key.NewDecrypter() error = %v", err)
		return
	}

	if decrypter == nil {
		t.Error("ChaCha20Key.NewDecrypter() returned nil decrypter")
	}

	// Verify it implements the Decrypter interface
	var _ types.Decrypter = decrypter
}

func TestNewRandomNonce(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "successful nonce generation",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce, err := NewRandomNonce()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRandomNonce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify nonce is not all zeros
				allZeros := true
				for _, b := range nonce {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Error("NewRandomNonce() returned all-zero nonce")
				}
			}
		})
	}
}

func TestChaCha20PolyEncrypter_Encrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypter := &ChaCha20PolyEncrypter{Key: *key}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "small data",
			data:    []byte("hello world"),
			wantErr: false,
		},
		{
			name:    "large data",
			data:    make([]byte, 1024),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill large data with random bytes
			if len(tt.data) > 20 {
				io.ReadFull(rand.Reader, tt.data)
			}

			encrypted, err := encrypter.Encrypt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ChaCha20PolyEncrypter.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify encrypted data format: [nonce][ciphertext+tag]
				expectedLen := NonceSize + len(tt.data) + TagSize
				if len(encrypted) != expectedLen {
					t.Errorf("ChaCha20PolyEncrypter.Encrypt() encrypted length = %d, want %d", len(encrypted), expectedLen)
				}
				// Verify encrypted data is different from original (unless empty)
				if len(tt.data) > 0 {
					if bytes.Equal(encrypted[NonceSize:NonceSize+len(tt.data)], tt.data) {
						t.Error("ChaCha20PolyEncrypter.Encrypt() returned data identical to plaintext")
					}
				}
			}
		})
	}
}

func TestChaCha20PolyEncrypter_EncryptWithAd(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypter := &ChaCha20PolyEncrypter{Key: *key}

	tests := []struct {
		name    string
		data    []byte
		ad      []byte
		wantErr bool
	}{
		{
			name:    "empty data with ad",
			data:    []byte{},
			ad:      []byte("additional data"),
			wantErr: false,
		},
		{
			name:    "data with ad",
			data:    []byte("hello world"),
			ad:      []byte("additional data"),
			wantErr: false,
		},
		{
			name:    "data without ad",
			data:    []byte("hello world"),
			ad:      nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := encrypter.EncryptWithAd(tt.data, tt.ad)
			if (err != nil) != tt.wantErr {
				t.Errorf("ChaCha20PolyEncrypter.EncryptWithAd() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify encrypted data format: [nonce][ciphertext+tag]
				expectedLen := NonceSize + len(tt.data) + TagSize
				if len(encrypted) != expectedLen {
					t.Errorf("ChaCha20PolyEncrypter.EncryptWithAd() encrypted length = %d, want %d", len(encrypted), expectedLen)
				}
			}
		})
	}
}

func TestChaCha20PolyDecrypter_Decrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypter := &ChaCha20PolyEncrypter{Key: *key}
	decrypter := &ChaCha20PolyDecrypter{Key: *key}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "small data",
			data:    []byte("hello world"),
			wantErr: false,
		},
		{
			name:    "large data",
			data:    make([]byte, 1024),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill large data with random bytes
			if len(tt.data) > 20 {
				io.ReadFull(rand.Reader, tt.data)
			}

			// Encrypt first
			encrypted, err := encrypter.Encrypt(tt.data)
			if err != nil {
				t.Fatal(err)
			}

			// Then decrypt
			decrypted, err := decrypter.Decrypt(encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("ChaCha20PolyDecrypter.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if !bytes.Equal(decrypted, tt.data) {
					t.Error("ChaCha20PolyDecrypter.Decrypt() decrypted data doesn't match original")
				}
			}
		})
	}
}

func TestChaCha20PolyDecrypter_DecryptWithAd(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypter := &ChaCha20PolyEncrypter{Key: *key}
	decrypter := &ChaCha20PolyDecrypter{Key: *key}

	tests := []struct {
		name    string
		data    []byte
		ad      []byte
		wantErr bool
	}{
		{
			name:    "empty data with ad",
			data:    []byte{},
			ad:      []byte("additional data"),
			wantErr: false,
		},
		{
			name:    "data with ad",
			data:    []byte("hello world"),
			ad:      []byte("additional data"),
			wantErr: false,
		},
		{
			name:    "data without ad",
			data:    []byte("hello world"),
			ad:      nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt first
			encrypted, err := encrypter.EncryptWithAd(tt.data, tt.ad)
			if err != nil {
				t.Fatal(err)
			}

			// Then decrypt
			decrypted, err := decrypter.DecryptWithAd(encrypted, tt.ad)
			if (err != nil) != tt.wantErr {
				t.Errorf("ChaCha20PolyDecrypter.DecryptWithAd() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if !bytes.Equal(decrypted, tt.data) {
					t.Error("ChaCha20PolyDecrypter.DecryptWithAd() decrypted data doesn't match original")
				}
			}
		})
	}
}

func TestChaCha20PolyDecrypter_DecryptInvalidData(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	decrypter := &ChaCha20PolyDecrypter{Key: *key}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "too short data",
			data:    make([]byte, NonceSize+TagSize-1),
			wantErr: true,
		},
		{
			name:    "corrupted data",
			data:    make([]byte, NonceSize+TagSize+10),
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill with random bytes for corrupted data test
			if len(tt.data) > 0 {
				io.ReadFull(rand.Reader, tt.data)
			}

			_, err := decrypter.Decrypt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ChaCha20PolyDecrypter.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestChaCha20PolyDecrypter_DecryptWithWrongAd(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypter := &ChaCha20PolyEncrypter{Key: *key}
	decrypter := &ChaCha20PolyDecrypter{Key: *key}

	data := []byte("hello world")
	ad := []byte("additional data")
	wrongAd := []byte("wrong additional data")

	// Encrypt with AD
	encrypted, err := encrypter.EncryptWithAd(data, ad)
	if err != nil {
		t.Fatal(err)
	}

	// Try to decrypt with wrong AD
	_, err = decrypter.DecryptWithAd(encrypted, wrongAd)
	if err == nil {
		t.Error("ChaCha20PolyDecrypter.DecryptWithAd() should fail with wrong AD")
	}

	// Try to decrypt with no AD when AD was used
	_, err = decrypter.DecryptWithAd(encrypted, nil)
	if err == nil {
		t.Error("ChaCha20PolyDecrypter.DecryptWithAd() should fail with nil AD when AD was used")
	}
}

func TestChaCha20EncryptDecryptRoundtrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypter, err := key.NewEncrypter()
	if err != nil {
		t.Fatal(err)
	}

	decrypter, err := key.NewDecrypter()
	if err != nil {
		t.Fatal(err)
	}

	testData := [][]byte{
		{},
		[]byte("hello"),
		[]byte("hello world"),
		make([]byte, 1000),
		make([]byte, 10000),
	}

	for i, data := range testData {
		t.Run(fmt.Sprintf("test_%d", i), func(t *testing.T) {
			// Fill large data with random bytes
			if len(data) > 20 {
				io.ReadFull(rand.Reader, data)
			}

			encrypted, err := encrypter.Encrypt(data)
			if err != nil {
				t.Fatal(err)
			}

			decrypted, err := decrypter.Decrypt(encrypted)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(data, decrypted) {
				t.Error("Round-trip encryption/decryption failed")
			}
		})
	}
}

// Benchmark tests
func BenchmarkChaCha20KeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKey()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20Encrypt(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}

	encrypter := &ChaCha20PolyEncrypter{Key: *key}
	data := make([]byte, 1024)
	io.ReadFull(rand.Reader, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20Decrypt(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}

	encrypter := &ChaCha20PolyEncrypter{Key: *key}
	decrypter := &ChaCha20PolyDecrypter{Key: *key}
	data := make([]byte, 1024)
	io.ReadFull(rand.Reader, data)

	encrypted, err := encrypter.Encrypt(data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decrypter.Decrypt(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewRandomNonce(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewRandomNonce()
		if err != nil {
			b.Fatal(err)
		}
	}
}
