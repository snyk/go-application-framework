package utils

import (
	"strconv"
)

func ToBool(value interface{}) bool {
	if value == nil {
		return false
	}

	switch v := value.(type) {
	case bool:
		return v
	case string:
		boolResult, err := strconv.ParseBool(v)
		if err != nil {
			return false
		}
		return boolResult
	}

	return false
}
