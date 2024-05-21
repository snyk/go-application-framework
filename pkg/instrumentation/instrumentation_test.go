package instrumentation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DetermineStage(t *testing.T) {
	t.Run("returns dev by default", func(t *testing.T) {
		assert.Equal(t, "dev", DetermineStage(false))
	})

	t.Run("returns cicd for matching environments", func(t *testing.T) {
		t.Setenv("CI", "true")
		assert.Equal(t, "cicd", DetermineStage(true))
	})
}
