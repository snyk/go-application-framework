package config_workflow

import (
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ConfigSet(t *testing.T) {
	t.Run("stores each pair as a string, keeping the other keys", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, `{"z":"1", "num": 1.50}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_SET, "k=v", "n=2.50", "b=true")

		require.NoError(t, err)
		assert.Equal(t, "k updated\nn updated\nb updated\n", out)
		assert.Equal(t, `{"b":"true","k":"v","n":"2.50","num":1.50,"z":"1"}`, readFile(t, test.file))
	})

	t.Run("creates a missing file", func(t *testing.T) {
		test := newConfigTest(t)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_SET, "k=v")

		require.NoError(t, err)
		assert.Equal(t, "k updated\n", out)
		assert.Equal(t, `{"k":"v"}`, readFile(t, test.file))
	})

	for name, tc := range map[string]struct{ arg, file string }{
		"splits on the first =":            {"k=a=b", `{"k":"a=b"}`},
		"stores an empty value":            {"k=", `{"k":""}`},
		"stores a value with a newline":    {"k=a\nb", `{"k":"a\nb"}`},
		"stores a dotted key flat":         {"a.b=c", `{"a.b":"c"}`},
		"stores the key as typed, not api": {"snyk_token=x", `{"snyk_token":"x"}`},
	} {
		t.Run(name, func(t *testing.T) {
			test := newConfigTest(t)

			_, err := test.invoke(t, WORKFLOWID_CONFIG_SET, tc.arg)

			require.NoError(t, err)
			assert.Equal(t, tc.file, readFile(t, test.file))
		})
	}

	t.Run("prints nothing and changes nothing without an argument", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, `{"KEY":"1"}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_SET)

		require.NoError(t, err)
		assert.Empty(t, out)
		assert.Equal(t, `{"KEY":"1"}`, readFile(t, test.file))
	})

	for name, args := range map[string][]string{
		"a key without =":               {"KEY"},
		"an empty key":                  {"=x"},
		"a valid pair before a bad one": {"k=v", "KEY"},
	} {
		t.Run("changes nothing given "+name, func(t *testing.T) {
			test := newConfigTest(t)
			writeFile(t, test.file, `{"KEY":"1"}`)

			out, err := test.invoke(t, WORKFLOWID_CONFIG_SET, args...)

			assertUsageError(t, err)
			assert.Empty(t, out)
			assert.Equal(t, `{"KEY":"1"}`, readFile(t, test.file))
		})
	}

	t.Run("fails on invalid JSON and leaves the file untouched", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, `{"a":`)

		_, err := test.invoke(t, WORKFLOWID_CONFIG_SET, "k=v")

		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, `{"a":`, readFile(t, test.file))
	})

	t.Run("writes the file of the selected profile only", func(t *testing.T) {
		test, defaultFile := newProfileTest(t)
		writeFile(t, defaultFile, `{"a":"default"}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_SET, "a=work")

		require.NoError(t, err)
		assert.Equal(t, "a updated\n", out)
		assert.Equal(t, `{"a":"work"}`, readFile(t, test.file))
		assert.Equal(t, `{"a":"default"}`, readFile(t, defaultFile))
	})
}
