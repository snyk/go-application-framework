package utils

import (
	"errors"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
)

func TestAddMetaDataToErr(t *testing.T) {
	t.Run("adds metadata to error catalog error", func(t *testing.T) {
		err := snyk_errors.Error{
			ID: "some-id",
		}
		meta := map[string]any{
			"foo": "bar",
		}
		errWithMeta := AddMetaDataToErr(err, meta)

		// Type assertion to access the Meta field
		var snykErr snyk_errors.Error
		ok := errors.As(errWithMeta, &snykErr)
		if !ok {
			t.Fatal("expected errWithMeta to be of type snyk_errors.Error")
		}
		assert.Equal(t, meta, snykErr.Meta)
		assert.Nil(t, err.Meta)
	})

	t.Run("returns original error if not error catalog error", func(t *testing.T) {
		err := errors.New("my first error")
		meta := map[string]any{
			"foo": "bar",
		}
		errWithMeta := AddMetaDataToErr(err, meta)
		assert.Equal(t, err, errWithMeta)
	})
}
