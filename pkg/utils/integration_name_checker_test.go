package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSnykIde(t *testing.T) {
	testset := map[string]bool{
		"something":     false,
		"Vs_coDE":       true,
		"JETBRAINS_IDE": true,
	}
	for k, expected := range testset {
		t.Run(k, func(t *testing.T) {
			actual := IsSnykIde(k)
			assert.Equal(t, expected, actual)
		})
	}
}
func TestIsRunningFromNpm(t *testing.T) {
	testset := map[string]bool{
		"TS_BINARY_WRAPPER":     true,
		"NOT_TS_BINARY_WRAPPER": false,
	}
	for k, expected := range testset {
		t.Run(k, func(t *testing.T) {
			actual := IsRunningFromNpm(k)
			assert.Equal(t, expected, actual)
		})
	}
}
