package rand

import (
	"math/big"
	"testing"
)

func TestSecureReader_Read(t *testing.T) {
	tests := []struct {
		name       string
		bufferSize int
		wantErr    bool
	}{
		{
			name:       "small buffer",
			bufferSize: 16,
			wantErr:    false,
		},
		{
			name:       "medium buffer",
			bufferSize: 64,
			wantErr:    false,
		},
		{
			name:       "large buffer",
			bufferSize: 1024,
			wantErr:    false,
		},
		{
			name:       "empty buffer",
			bufferSize: 0,
			wantErr:    false,
		},
	}

	sr := NewSecureReader()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.bufferSize)
			n, err := sr.Read(buf)

			if (err != nil) != tt.wantErr {
				t.Errorf("SecureReader.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if n != tt.bufferSize {
				t.Errorf("SecureReader.Read() = %v, want %v", n, tt.bufferSize)
			}

			// Check that buffer is not all zeros (basic randomness test)
			if tt.bufferSize > 0 {
				allZeros := true
				for _, b := range buf {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Error("SecureReader.Read() returned all zeros")
				}
			}
		})
	}
}

func TestSecureReader_ReadBigInt(t *testing.T) {
	tests := []struct {
		name    string
		max     *big.Int
		wantErr bool
	}{
		{
			name:    "small max",
			max:     big.NewInt(100),
			wantErr: false,
		},
		{
			name:    "large max",
			max:     new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil),
			wantErr: false,
		},
		{
			name:    "zero max",
			max:     big.NewInt(0),
			wantErr: true,
		},
		{
			name:    "negative max",
			max:     big.NewInt(-1),
			wantErr: true,
		},
	}

	sr := NewSecureReader()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sr.ReadBigInt(tt.max)

			if (err != nil) != tt.wantErr {
				t.Errorf("SecureReader.ReadBigInt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if result.Cmp(big.NewInt(0)) < 0 {
					t.Error("SecureReader.ReadBigInt() returned negative number")
				}
				if result.Cmp(tt.max) >= 0 {
					t.Error("SecureReader.ReadBigInt() returned number >= max")
				}
			}
		})
	}
}

func TestSecureReader_ReadBigIntInRange(t *testing.T) {
	tests := []struct {
		name    string
		min     *big.Int
		max     *big.Int
		wantErr bool
	}{
		{
			name:    "valid range",
			min:     big.NewInt(10),
			max:     big.NewInt(100),
			wantErr: false,
		},
		{
			name:    "large range",
			min:     big.NewInt(1),
			max:     new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil),
			wantErr: false,
		},
		{
			name:    "min equals max",
			min:     big.NewInt(50),
			max:     big.NewInt(50),
			wantErr: true,
		},
		{
			name:    "min greater than max",
			min:     big.NewInt(100),
			max:     big.NewInt(50),
			wantErr: true,
		},
	}

	sr := NewSecureReader()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sr.ReadBigIntInRange(tt.min, tt.max)

			if (err != nil) != tt.wantErr {
				t.Errorf("SecureReader.ReadBigIntInRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if result.Cmp(tt.min) < 0 {
					t.Error("SecureReader.ReadBigIntInRange() returned number < min")
				}
				if result.Cmp(tt.max) >= 0 {
					t.Error("SecureReader.ReadBigIntInRange() returned number >= max")
				}
			}
		})
	}
}

func TestValidateEntropy(t *testing.T) {
	sr := NewSecureReader()

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "small data skips validation",
			data: make([]byte, 16),
			want: true,
		},
		{
			name: "all zeros fails validation",
			data: make([]byte, 64),
			want: false,
		},
		{
			name: "alternating pattern fails validation",
			data: func() []byte {
				data := make([]byte, 64)
				for i := range data {
					data[i] = byte(i % 2)
				}
				return data
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sr.validateEntropy(tt.data)
			if got != tt.want {
				t.Errorf("validateEntropy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGlobalFunctions(t *testing.T) {
	t.Run("Read", func(t *testing.T) {
		buf := make([]byte, 32)
		n, err := Read(buf)
		if err != nil {
			t.Errorf("Read() error = %v", err)
		}
		if n != 32 {
			t.Errorf("Read() = %v, want 32", n)
		}
	})

	t.Run("ReadBigInt", func(t *testing.T) {
		max := big.NewInt(1000)
		result, err := ReadBigInt(max)
		if err != nil {
			t.Errorf("ReadBigInt() error = %v", err)
		}
		if result.Cmp(big.NewInt(0)) < 0 || result.Cmp(max) >= 0 {
			t.Errorf("ReadBigInt() = %v, want in range [0, %v)", result, max)
		}
	})

	t.Run("ReadBigIntInRange", func(t *testing.T) {
		min := big.NewInt(100)
		max := big.NewInt(1000)
		result, err := ReadBigIntInRange(min, max)
		if err != nil {
			t.Errorf("ReadBigIntInRange() error = %v", err)
		}
		if result.Cmp(min) < 0 || result.Cmp(max) >= 0 {
			t.Errorf("ReadBigIntInRange() = %v, want in range [%v, %v)", result, min, max)
		}
	})
}

// Benchmark tests
func BenchmarkSecureReader_Read(b *testing.B) {
	sr := NewSecureReader()
	buf := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sr.Read(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSecureReader_ReadBigInt(b *testing.B) {
	sr := NewSecureReader()
	max := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sr.ReadBigInt(max)
		if err != nil {
			b.Fatal(err)
		}
	}
}
