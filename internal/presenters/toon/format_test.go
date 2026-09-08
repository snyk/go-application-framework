package toon_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters/toon"
)

func TestFormatControlCharacters(t *testing.T) {
	t.Parallel()

	for r := rune(0); r < 0x20; r++ {
		input := "before" + string(r) + "after"
		escaped := fmt.Sprintf(`\u%04x`, r)
		if short, ok := map[rune]string{'\n': `\n`, '\r': `\r`, '\t': `\t`}[r]; ok {
			escaped = short
		}
		expected := `"before` + escaped + `after"`
		scalar, err := toon.FormatScalarValue(input)
		require.NoError(t, err)
		assert.Equal(t, expected, scalar)
		cell, err := toon.FormatTabularField(input)
		require.NoError(t, err)
		assert.Equal(t, expected, cell)
		assert.Equal(t, expected, toon.FormatKey(input))
	}
}

func TestFormatTabularField_quotesComma(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ input, expected string }{
		{`Doe, Jane`, `"Doe, Jane"`},
		{`rule,with"comma"`, `"rule,with\"comma\""`},
	} {
		got, err := toon.FormatTabularField(tc.input)
		require.NoError(t, err)
		assert.Equal(t, tc.expected, got)
	}
}

func TestFormatTabularField_plainValueUnquoted(t *testing.T) {
	t.Parallel()

	got, err := toon.FormatTabularField("AWS Access Token")
	require.NoError(t, err)
	assert.Equal(t, "AWS Access Token", got)
}

func TestFormatScalarValue_quotesHashPrefix(t *testing.T) {
	t.Parallel()

	got, err := toon.FormatScalarValue("#not a comment")
	require.NoError(t, err)
	assert.Equal(t, `"#not a comment"`, got)
}

func TestFormatScalarValue_summaryUnquoted(t *testing.T) {
	t.Parallel()

	got, err := toon.FormatScalarValue("3 unique vulns (4 paths) | 1 high 1 medium 1 low | 2 fixable")
	require.NoError(t, err)
	assert.Equal(t, "3 unique vulns (4 paths) | 1 high 1 medium 1 low | 2 fixable", got)
}
