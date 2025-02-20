package utils

import (
	"errors"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// AddMetaDataToErr adds the provided metadata to the Error catalog error's metadata map.
func AddMetaDataToErr(err error, meta map[string]any) error {
	snykErr := snyk_errors.Error{}
	if !errors.As(err, &snykErr) {
		return err
	}

	for k, v := range meta {
		snyk_errors.WithMeta(k, v)(&snykErr)
	}

	return snykErr
}
