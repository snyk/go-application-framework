package utils

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetTargetId(t *testing.T) {
	t.Run("handles a filesystem directory path", func(t *testing.T) {
		tempDir := t.TempDir()
		targetId, err := GetTargetId(tempDir)
		assert.NoError(t, err)

		pattern := `^pkg:filesystem/[a-fA-F0-9]{64}/001$`

		matched, err := regexp.MatchString(pattern, targetId)
		assert.NoError(t, err)
		assert.True(t, matched)
	})

	t.Run("handles a file directory path", func(t *testing.T) {
		tempDir := t.TempDir()
		tempFile1 := filepath.Join(tempDir, "test1.ts")
		targetId, err := GetTargetId(tempFile1)
		assert.NoError(t, err)

		pattern := `^pkg:filesystem/[a-fA-F0-9]{64}/001#test1.ts$`

		matched, err := regexp.MatchString(pattern, targetId)
		assert.NoError(t, err)
		assert.True(t, matched)
	})

	t.Run("")
}
