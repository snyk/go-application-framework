package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetTemporaryDirectory_usesPlatformSeparator(t *testing.T) {
	actual := GetTemporaryDirectory(filepath.Join("base", "cache"), "1.2.3")

	expected := filepath.Join("base", "cache", "1.2.3", "tmp", fmt.Sprintf("pid%d", os.Getpid()))
	assert.Equal(t, expected, actual)
	// filepath.Clean is a no-op only when the separators are already correct.
	assert.Equal(t, filepath.Clean(actual), actual)
}

func Test_CreateDirectory_doesNotDeriveExtraSegments(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "1.2.3", "tmp", "pid999")

	require.NoError(t, CreateDirectory(target))

	assert.DirExists(t, target)
	// The bug this replaces: CreateAllDirectories(target, version) also created
	// target/<version>/tmp/pid<PID> underneath.
	entries, err := os.ReadDir(target)
	require.NoError(t, err)
	assert.Empty(t, entries, "no nested directories should be created")
}

func Test_CreateDirectory_isIdempotent(t *testing.T) {
	target := filepath.Join(t.TempDir(), "nested", "dir")

	require.NoError(t, CreateDirectory(target))
	require.NoError(t, CreateDirectory(target))

	assert.DirExists(t, target)
}
