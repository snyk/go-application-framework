package utils

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateFilePath(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "newDir", "file.txt")
	pathToCreate := filepath.Dir(filePath)
	err := CreateFilePath(filePath)
	assert.NoError(t, err)
	assert.DirExists(t, pathToCreate)
}
