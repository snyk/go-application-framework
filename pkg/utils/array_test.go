package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Merge(t *testing.T) {
	input1 := []string{"h", "o", "l"}
	input2 := []string{"l", "a", "!"}
	expectedOutput := []string{"h", "o", "l", "a", "!"}
	actualOutput := Merge(input1, input2)
	assert.Equal(t, expectedOutput, actualOutput)
}
