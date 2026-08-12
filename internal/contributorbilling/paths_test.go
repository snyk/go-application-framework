package contributorbilling

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWaitBudget(t *testing.T) {
	t.Parallel()

	assert.Equal(t, DefaultTimeout, WaitBudget(0))
	assert.Equal(t, 5*time.Second, WaitBudget(5*time.Second))
}

func TestResolveRepoPath_AbsolutizesRelativePath(t *testing.T) {
	t.Parallel()

	abs := resolveRepoPath(".")
	assert.True(t, filepath.IsAbs(abs))
}
