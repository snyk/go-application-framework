package utils

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Contains(t *testing.T) {
	input := []string{"h", "o", "l", "a", "!"}
	assert.True(t, Contains(input, "h"))
	assert.False(t, Contains(input, "x"))
}

func Test_RemoveSimilar(t *testing.T) {
	input := []string{"h", "o", "l", "a", "!"}
	expectedOutput := []string{"h", "o", "l", "!"}
	actualOutput := RemoveSimilar(input, "a")
	assert.Equal(t, expectedOutput, actualOutput)
}

func Test_Merge(t *testing.T) {
	input1 := []string{"h", "o", "l"}
	input2 := []string{"l", "a", "!"}
	expectedOutput := []string{"h", "o", "l", "a", "!"}
	actualOutput := Merge(input1, input2)
	assert.Equal(t, expectedOutput, actualOutput)
}

func Test_ToKeyValueMap(t *testing.T) {
	input := []string{"key1=value1", "key2=value2"}
	expectedOutput := map[string]string{"key1": "value1", "key2": "value2"}
	actualOutput := ToKeyValueMap(input, "=")
	assert.Equal(t, expectedOutput, actualOutput)
}

func Test_ToSlice(t *testing.T) {
	input := map[string]string{"key1": "value1", "key2": "value2"}
	expectedOutput := []string{"key1=value1", "key2=value2"}
	actualOutput := ToSlice(input, "=")
	sort.Strings(expectedOutput)
	sort.Strings(actualOutput)
	assert.Equal(t, expectedOutput, actualOutput)
}

func Test_Remove(t *testing.T) {
	input := map[string]string{"key1": "value1", "key2": "value2"}
	expectedOutput := map[string]string{"key1": "value1"}

	actualOutput := Remove(input, "key2")
	assert.Equal(t, expectedOutput, actualOutput)
}

func Test_FindKeyCaseInsensitive(t *testing.T) {
	input := map[string]string{"key1": "value1", "key2": "value2"}
	expectedOutput := true
	_, keyFound := FindKeyCaseInsensitive(input, "KEY1")
	assert.Equal(t, expectedOutput, keyFound)
}

func Test_FindValueCaseInsensitive(t *testing.T) {
	input := map[string]string{"key1": "value1", "key2": "value2"}
	expectedValue := "value1"
	expectedValueFound := true
	value, valueFound := FindValueCaseInsensitive(input, "KEY1")
	assert.Equal(t, expectedValueFound, valueFound)
	assert.Equal(t, expectedValue, value)
}
