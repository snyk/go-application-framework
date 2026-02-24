package conversion

import (
	"fmt"
	"strconv"
)

// ToInt converts an interface{} value to int interpreting strings and float values as base 10 integers
func ToInt(value interface{}) (int, error) {
	if value == nil {
		return 0, fmt.Errorf("value is nil")
	}

	switch v := value.(type) {
	case string:
		i, err := strconv.ParseInt(v, 10, 0)
		if err != nil {
			return 0, fmt.Errorf("failed to parse string as int: %w", err)
		}
		return int(i), nil
	case float32:
		return int(v), nil
	case float64:
		return int(v), nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	}

	return 0, fmt.Errorf("value is not convertible to int")
}
