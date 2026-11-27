package configuration

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CheckStorage(t *testing.T) {
	const (
		noHomeDirectory    = "the home directory could not be determined"
		pinnedFileUnusable = "the configured configuration file cannot be used"
	)
	withoutHomeDirectory := func(t *testing.T) Configuration {
		t.Helper()
		t.Setenv("HOME", "")
		t.Setenv("USERPROFILE", "")
		t.Chdir(t.TempDir())
		c := NewWithOpts(WithFiles("snyk"))
		require.Nil(t, c.GetStorage(), "precondition: no storage without a home directory")
		return c
	}
	tests := []struct {
		name   string
		config func(t *testing.T) Configuration
		reason string // empty when the configuration has the storage it needs
	}{
		{
			name:   "file without a home directory is refused",
			config: withoutHomeDirectory,
			reason: noHomeDirectory,
		},
		{
			name: "file with an empty storage is refused",
			config: func(t *testing.T) Configuration {
				t.Helper()
				c := withoutHomeDirectory(t)
				c.SetStorage(&EmptyStorage{})
				return c
			},
			reason: noHomeDirectory,
		},
		{
			name: "file with a storage is accepted",
			config: func(t *testing.T) Configuration {
				t.Helper()
				c := withoutHomeDirectory(t)
				c.SetStorage(NewJsonStorage(filepath.Join(t.TempDir(), "snyk.json")))
				return c
			},
		},
		{
			name: "rejected pinned file is refused",
			config: func(t *testing.T) Configuration {
				t.Helper()
				captureLog(t)
				return NewWithOpts(WithPinnedFile("snyk.json"))
			},
			reason: pinnedFileUnusable,
		},
		{
			name: "usable pinned file is accepted",
			config: func(t *testing.T) Configuration {
				t.Helper()
				return NewWithOpts(WithPinnedFile(filepath.Join(t.TempDir(), "snyk.json")))
			},
		},
		{
			name:   "in-memory configuration is accepted",
			config: func(*testing.T) Configuration { return NewWithOpts() },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.config(t)
			// workflows get a clone of the engine configuration
			for _, c := range []Configuration{config, config.Clone()} {
				err := CheckStorage(c)
				if tc.reason != "" {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tc.reason)
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}

func Test_HasStorage(t *testing.T) {
	c := NewWithOpts()
	assert.False(t, HasStorage(c), "no storage")
	c.SetStorage(&EmptyStorage{})
	assert.False(t, HasStorage(c), "an empty storage stores nothing")
	c.SetStorage(NewJsonStorage(filepath.Join(t.TempDir(), "snyk.json")))
	assert.True(t, HasStorage(c))
}
