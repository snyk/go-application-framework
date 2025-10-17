package errorutils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Test Helper Functions
// ============================================================================

func createTestConfig(directories []string) configuration.Configuration {
	config := configuration.New()
	config.Set(configuration.INPUT_DIRECTORY, directories)
	return config
}

// ============================================================================
// Test Functions
// ============================================================================

func TestWorkingDirectoryBehavior(t *testing.T) {
	testDirs := []string{"/home/user/project", "/tmp/build"}

	t.Run("can set and retrieve working directories", func(t *testing.T) {
		err := cli.NewGenericNetworkError(
			"Network error occurred",
			WithWorkingDirectory(testDirs),
		)

		retrievedDirs, found := GetWorkingDirectory(&err)
		assert.True(t, found)
		assert.Equal(t, testDirs, retrievedDirs)
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

func TestProcessSnykErrorsInChain(t *testing.T) {
	// Create a processor that counts Snyk errors
	var processedCount int
	processor := func(_ *snyk_errors.Error) {
		processedCount++
	}

	t.Run("handles plain Snyk error", func(t *testing.T) {
		processedCount = 0
		originalErr := cli.NewGeneralCLIFailureError("Test error")
		result := ProcessSnykErrorsInChain(originalErr, processor)

		// Should be the same type
		assert.IsType(t, snyk_errors.Error{}, result)
		// Should have processed exactly 1 Snyk error
		assert.Equal(t, 1, processedCount)
	})

	t.Run("handles wrapped Snyk error", func(t *testing.T) {
		processedCount = 0
		originalErr := fmt.Errorf("wrapper: %w", cli.NewGeneralCLIFailureError("Wrapped error"))
		result := ProcessSnykErrorsInChain(originalErr, processor)

		// Should be a wrapped error (has Unwrap method)
		_, hasUnwrap := result.(interface{ Unwrap() error })
		assert.True(t, hasUnwrap)
		// Should have processed exactly 1 Snyk error
		assert.Equal(t, 1, processedCount)
	})

	t.Run("handles joined error with multiple Snyk errors", func(t *testing.T) {
		processedCount = 0
		originalErr := errors.Join(
			errors.New("context error"),
			cli.NewGeneralCLIFailureError("First Snyk error"),
			errors.New("another context"),
			fmt.Errorf("wrapper: %w", cli.NewGeneralCLIFailureError("Second Wrapped error")),
		)

		result := ProcessSnykErrorsInChain(originalErr, processor)

		// Should be a joined error (has Unwrap method returning []error)
		_, hasUnwrapSlice := result.(interface{ Unwrap() []error })
		assert.True(t, hasUnwrapSlice)
		// Should have processed exactly 2 Snyk errors
		assert.Equal(t, 2, processedCount)
	})

	t.Run("handles non-Snyk error", func(t *testing.T) {
		processedCount = 0
		originalErr := errors.New("regular error")
		result := ProcessSnykErrorsInChain(originalErr, processor)

		// Should be unchanged
		assert.Equal(t, originalErr, result)
		// Should not have processed any Snyk errors
		assert.Equal(t, 0, processedCount)
	})

	t.Run("handles nil error", func(t *testing.T) {
		processedCount = 0
		result := ProcessSnykErrorsInChain(nil, processor)
		// Should return nil
		assert.Nil(t, result)
		// Should not have processed any Snyk errors
		assert.Equal(t, 0, processedCount)
	})
}

func TestDecorateTestError(t *testing.T) {
	testDirs := []string{"/test/path"}
	config := createTestConfig(testDirs)

	// Use a simple Snyk error for all tests
	testErr := cli.NewGeneralCLIFailureError("Test error")

	t.Run("adds metadata on a single error", func(t *testing.T) {
		result := DecorateTestError(testErr, config)

		// Should not have metadata (nil list)
		var snykErr snyk_errors.Error
		assert.True(t, errors.As(result, &snykErr))
		dirs, found := GetWorkingDirectory(&snykErr)
		assert.True(t, found)
		assert.Equal(t, testDirs, dirs)
	})

	t.Run("does not add metadata when directories are nil", func(t *testing.T) {
		nilConfig := configuration.New()
		nilConfig.Set(configuration.INPUT_DIRECTORY, nil)

		result := DecorateTestError(testErr, nilConfig)

		// Should not have metadata (nil list)
		var snykErr snyk_errors.Error
		assert.True(t, errors.As(result, &snykErr))
		dirs, found := GetWorkingDirectory(&snykErr)
		assert.False(t, found)
		assert.Equal(t, []string{}, dirs)
	})

	t.Run("handles non-Snyk errors unchanged", func(t *testing.T) {
		testDirs := []string{"/test/path"}
		config := createTestConfig(testDirs)
		regularErr := errors.New("regular error")

		result := DecorateTestError(regularErr, config)

		// Should be unchanged
		assert.Equal(t, regularErr, result)
	})

	t.Run("handles nil error", func(t *testing.T) {
		testDirs := []string{"/test/path"}
		config := createTestConfig(testDirs)

		result := DecorateTestError(nil, config)
		// Should return nil
		assert.Nil(t, result)
	})
}
