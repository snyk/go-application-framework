package errorutils

import (
	"testing"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
)

func TestWorkingDirectoryBehavior(t *testing.T) {
	t.Run("can set and retrieve working directories", func(t *testing.T) {
		directories := []string{"/home/user/project", "/tmp/build"}

		err := cli.NewGenericNetworkError(
			"Network error occurred",
			WithWorkingDirectory(directories),
		)

		retrievedDirs, found := GetWorkingDirectory(&err)
		assert.True(t, found)
		assert.Equal(t, directories, retrievedDirs)
	})

	t.Run("handles edge cases", func(t *testing.T) {
		t.Run("empty directory list", func(t *testing.T) {
			err := cli.NewGenericNetworkError("Test error", WithWorkingDirectory([]string{}))
			retrievedDirs, found := GetWorkingDirectory(&err)
			assert.True(t, found)
			assert.Equal(t, []string{}, retrievedDirs)
		})

		t.Run("nil directory list", func(t *testing.T) {
			err := cli.NewGenericNetworkError("Test error", WithWorkingDirectory(nil))
			retrievedDirs, found := GetWorkingDirectory(&err)
			assert.False(t, found)
			assert.Equal(t, []string{}, retrievedDirs)
		})

		t.Run("no directories set", func(t *testing.T) {
			err := cli.NewGenericNetworkError("Test error")
			retrievedDirs, found := GetWorkingDirectory(&err)
			assert.False(t, found)
			assert.Equal(t, []string{}, retrievedDirs)
		})
	})

	t.Run("handles malformed metadata gracefully", func(t *testing.T) {
		testCases := []struct {
			name  string
			setup func() *snyk_errors.Error
		}{
			{
				name: "wrong type in metadata",
				setup: func() *snyk_errors.Error {
					return &snyk_errors.Error{
						Detail: "Test error",
						Meta: map[string]any{
							WorkingDirectoryKey: "not-a-slice",
						},
					}
				},
			},
			{
				name: "nil metadata",
				setup: func() *snyk_errors.Error {
					return &snyk_errors.Error{
						Detail: "Test error",
						Meta:   nil,
					}
				},
			},
			{
				name: "nil value in metadata",
				setup: func() *snyk_errors.Error {
					return &snyk_errors.Error{
						Detail: "Test error",
						Meta: map[string]any{
							WorkingDirectoryKey: nil,
						},
					}
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.setup()
				retrievedDirs, found := GetWorkingDirectory(err)
				assert.False(t, found)
				assert.Equal(t, []string{}, retrievedDirs)
			})
		}
	})

	t.Run("overwrites previous working directory when set multiple times", func(t *testing.T) {
		err := cli.NewGenericNetworkError(
			"Overwrite test",
			WithWorkingDirectory([]string{"/old/path"}),
			WithWorkingDirectory([]string{"/new/path"}),
		)

		retrievedDirs, found := GetWorkingDirectory(&err)
		assert.True(t, found)
		assert.Equal(t, []string{"/new/path"}, retrievedDirs)
	})

	t.Run("works with other error metadata", func(t *testing.T) {
		directories := []string{"/home/user/project"}

		err := cli.NewGenericNetworkError(
			"Combined metadata test",
			snyk_errors.WithMeta("requestId", "req-123"),
			WithWorkingDirectory(directories),
			snyk_errors.WithMeta("userId", "user-456"),
		)

		// Verify working directory is preserved
		retrievedDirs, found := GetWorkingDirectory(&err)
		assert.True(t, found)
		assert.Equal(t, directories, retrievedDirs)

		// Verify other metadata is also preserved
		assert.Equal(t, "req-123", err.Meta["requestId"])
		assert.Equal(t, "user-456", err.Meta["userId"])
	})

	t.Run("works with different error types", func(t *testing.T) {
		directories := []string{"/test/path"}

		// Test with CLI error
		cliErr := cli.NewGenericNetworkError("CLI error", WithWorkingDirectory(directories))
		cliDirs, cliFound := GetWorkingDirectory(&cliErr)
		assert.True(t, cliFound)
		assert.Equal(t, directories, cliDirs)

		// Test with manually created Snyk error
		snykErr := snyk_errors.Error{
			Detail: "Snyk error",
			Meta: map[string]any{
				WorkingDirectoryKey: directories,
			},
		}
		snykDirs, snykFound := GetWorkingDirectory(&snykErr)
		assert.True(t, snykFound)
		assert.Equal(t, directories, snykDirs)
	})
}
