package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Maps_MergeMaps(t *testing.T) {
	a := map[string]int{"a": 1, "b": 2}
	b := map[string]int{"b": 3, "c": 4}
	expected := map[string]int{"a": 1, "b": 3, "c": 4}

	actual := MergeMaps(a, b)
	assert.Equal(t, expected, actual)
}
