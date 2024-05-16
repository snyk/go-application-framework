package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSnykIde(t *testing.T) {
	testset := map[string]bool{
		"something":     false,
		"VS_CODE":       true,
		"JETBRAINS_IDE": true,
	}
	for k, expected := range testset {
		t.Run(k, func(t *testing.T) {
			actual := IsSnykIde(k)
			assert.Equal(t, expected, actual)
		})
	}
}
