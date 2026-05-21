package utils

import (
	"cmp"
	"slices"
)

// SortedMapKeys returns the keys of m in ascending order.
// Use it when deterministic iteration over a map is required (Go map iteration order is not defined),
// for example after encoding/json decoding into map[K]V.
func SortedMapKeys[K cmp.Ordered, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
