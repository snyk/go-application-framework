package errorutils

import (
	"errors"
	"fmt"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

const (
	WorkingDirectoryKey = "current-working-directory"
)

// WithWorkingDirectory creates an option that adds given working directory to the error
func WithWorkingDirectory(directories []string) snyk_errors.Option {
	return func(err *snyk_errors.Error) {
		if directories == nil {
			return
		}

		// use WithMeta to ensure that the meta is initialized
		snyk_errors.WithMeta(WorkingDirectoryKey, directories)(err)
	}
}

func GetWorkingDirectory(err *snyk_errors.Error) ([]string, bool) {
	if err.Meta == nil {
		return []string{}, false
	}

	directories, ok := err.Meta[WorkingDirectoryKey]
	if !ok || directories == nil {
		return []string{}, false
	}

	dirs, ok := directories.([]string)
	if !ok {
		return []string{}, false
	}

	return dirs, true
}

// SnykErrorProcessor is a function type that processes a Snyk error
type SnykErrorProcessor func(*snyk_errors.Error)

// ProcessSnykErrorsInChain iterates through an error chain and applies the processor function
// to each Snyk error found, while preserving the error chain structure.
func ProcessSnykErrorsInChain(err error, processor SnykErrorProcessor) error {
	if err == nil {
		return nil
	}

	// Handle different error types
	//nolint:errorlint // We need type switches here to handle different error types in specific order
	switch e := err.(type) {
	case snyk_errors.Error:
		// Plain Snyk error - process and return
		processor(&e)
		return e

	case interface{ Unwrap() error }:
		// Wrapped error - recursively process the unwrapped error
		unwrapped := ProcessSnykErrorsInChain(e.Unwrap(), processor)
		// Create new wrapped error with processed unwrapped error
		return fmt.Errorf("%s: %w", err.Error(), unwrapped)

	case interface{ Unwrap() []error }:
		// Joined error - process each error in the chain
		unwrapped := e.Unwrap()
		processed := make([]error, len(unwrapped))

		for i, subErr := range unwrapped {
			processed[i] = ProcessSnykErrorsInChain(subErr, processor)
		}

		// Create new joined error with processed errors
		return errors.Join(processed...)

	default:
		// Regular error - return as-is
		return err
	}
}

// DecorateTestError adds working directory metadata to all Snyk errors in the error chain
func DecorateTestError(err error, config configuration.Configuration) error {
	directories := config.GetStringSlice(configuration.INPUT_DIRECTORY)

	// Check if the original config value was nil (not just empty)
	originalValue := config.Get(configuration.INPUT_DIRECTORY)
	if originalValue == nil {
		// Don't add metadata if the original value was nil
		return err
	}

	processor := func(snykErr *snyk_errors.Error) {
		WithWorkingDirectory(directories)(snykErr)
	}

	return ProcessSnykErrorsInChain(err, processor)
}
