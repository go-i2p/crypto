package argon2

import (
	"fmt"
)

const (
	defaultTimeCost    uint32 = 3
	defaultMemoryCost  uint32 = 64 * 1024 // 64 MB
	defaultParallelism uint8  = 4
)

var (
	ErrInvalidKeyLength   error = fmt.Errorf("invalid key length")
	ErrInvalidTimeCost    error = fmt.Errorf("invalid time cost")
	ErrInvalidSalt        error = fmt.Errorf("invalid salt")
	ErrInsufficientMemory error = fmt.Errorf("insufficient memory cost")
	ErrInvalidParallelism error = fmt.Errorf("invalid parallelism")
)
