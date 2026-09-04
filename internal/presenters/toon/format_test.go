package toon_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters/toon"
)

func TestFormatTabularField_quotesComma(t *testing.T) {
	t.Parallel()

	got, err := toon.FormatTabularField(`rule,with"comma"`)
	require.NoError(t, err)
	assert.Equal(t, `"rule,with\"comma\""`, got)
}

func TestFormatTabularField_plainValueUnquoted(t *testing.T) {
	t.Parallel()

	got, err := toon.FormatTabularField("AWS Access Token")
	require.NoError(t, err)
	assert.Equal(t, "AWS Access Token", got)
}

func TestFormatScalarValue_summaryUnquoted(t *testing.T) {
	t.Parallel()

	got, err := toon.FormatScalarValue("3 unique vulns (4 paths) | 1 high 1 medium 1 low | 2 fixable")
	require.NoError(t, err)
	assert.Equal(t, "3 unique vulns (4 paths) | 1 high 1 medium 1 low | 2 fixable", got)
}
