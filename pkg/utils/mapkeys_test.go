package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortedMapKeys(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		testCases := []struct {
			name string
			m    map[string]int
			want []string
		}{
			{
				name: "sorted_values",
				m:    map[string]int{"b": 2, "a": 1, "c": 3},
				want: []string{"a", "b", "c"},
			},
			{
				name: "empty",
				m:    map[string]int{},
				want: []string{},
			},
			{
				name: "single_key",
				m:    map[string]int{"only": 1},
				want: []string{"only"},
			},
			{
				name: "keys_already_sorted",
				m:    map[string]int{"a": 1, "b": 2, "c": 3},
				want: []string{"a", "b", "c"},
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, SortedMapKeys(tc.m))
			})
		}
	})

	t.Run("int", func(t *testing.T) {
		testCases := []struct {
			name string
			m    map[int]string
			want []int
		}{
			{
				name: "sorted_values",
				m:    map[int]string{3: "c", 1: "a", 2: "b"},
				want: []int{1, 2, 3},
			},
			{
				name: "empty",
				m:    map[int]string{},
				want: []int{},
			},
			{
				name: "single_key",
				m:    map[int]string{42: "x"},
				want: []int{42},
			},
			{
				name: "negative_and_positive",
				m:    map[int]string{0: "z", -1: "a", 2: "b"},
				want: []int{-1, 0, 2},
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, SortedMapKeys(tc.m))
			})
		}
	})
}
