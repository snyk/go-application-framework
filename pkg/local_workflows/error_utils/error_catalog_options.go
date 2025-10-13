package errorutils

import (
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
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
