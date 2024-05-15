package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsCiEnvironment(t *testing.T) {
	scenarios := ciEnvironments

	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv(scenario, "foo")

			assert.True(t, IsCiEnvironment())
		})
	}
}
