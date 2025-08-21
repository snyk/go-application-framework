package utils

import "maps"

func MergeMaps[K comparable, V any](mapA map[K]V, mapB map[K]V) map[K]V {
	result := maps.Clone(mapA)

	for k, v := range mapB {
		result[k] = v
	}

	return result
}
