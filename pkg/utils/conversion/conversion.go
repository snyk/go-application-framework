package conversion

import (
	"fmt"
	"math"
	"strconv"
)

// ToInt64 converts an interface{} value to int64 interpreting strings and float values as base 10 integers
//
//nolint:gocyclo // complexity is from type cases, not logic branches
func ToInt64(value interface{}) (int64, error) {
	if value == nil {
		return 0, fmt.Errorf("value is nil")
	}

	switch v := value.(type) {
	case string:
		i, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse string as int64: %w", err)
		}
		return i, nil
	case float32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case uint:
		if uint64(v) > math.MaxInt64 {
			return 0, fmt.Errorf("value %d overflows int64", v)
		}
		return int64(v), nil
	case uint8:
		return int64(v), nil
	case uint16:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case uint64:
		if v > math.MaxInt64 {
			return 0, fmt.Errorf("value %d overflows int64", v)
		}
		return int64(v), nil
	}

	return 0, fmt.Errorf("value is not convertible to int64")
}

// ToInt converts an interface{} value to int interpreting strings and float values as base 10 integers
func ToInt(value interface{}) (int, error) {
	v, err := ToInt64(value)
	if err != nil {
		return 0, err
	}
	if v < math.MinInt || v > math.MaxInt {
		return 0, fmt.Errorf("value %d overflows int", v)
	}
	return int(v), nil
}
