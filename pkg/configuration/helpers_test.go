package configuration

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateHome points the home directory of the test at an empty temporary directory.
func isolateHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

// asViper returns the configuration as created by this package, to inspect its internals.
func asViper(t *testing.T, c Configuration) *extendedViper {
	t.Helper()
	ev, ok := c.(*extendedViper)
	require.True(t, ok)
	return ev
}

// foreignConfiguration is a Configuration that is not created by this package.
type foreignConfiguration struct {
	Configuration
}

// assertInMemoryWritesNothing checks that c is an in-memory configuration and that a persisted write creates nothing in dir.
func assertInMemoryWritesNothing(t *testing.T, c Configuration, dir string) {
	t.Helper()
	assert.Empty(t, c.GetFiles())
	assert.Nil(t, c.GetStorage())

	c.PersistInStorage("invalid_list_key")
	c.Set("invalid_list_key", "x")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// captureLog sends the standard logger to a buffer for the rest of the test and returns the buffer.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &buf
}
