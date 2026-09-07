package presenters_test

import (
	"bytes"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestNewUfmRenderer_registersTOON(t *testing.T) {
	t.Parallel()

	presenter := presenters.NewUfmRenderer(nil, configuration.NewWithOpts(), &bytes.Buffer{})
	err := presenter.RegisterMimeType(presenters.ApplicationTOONMimeType, func() (*template.Template, template.FuncMap, error) {
		tmpl, parseErr := template.New("dup").Parse("")
		return tmpl, nil, parseErr
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}
