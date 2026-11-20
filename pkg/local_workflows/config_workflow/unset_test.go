package config_workflow

import (
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ConfigUnset(t *testing.T) {
	t.Run("deletes the first key only, as typed", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, `{"snyk_token":"t", "api":"a", "b":"2", "num": 1.50}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_UNSET, "snyk_token", "b")

		require.NoError(t, err)
		assert.Equal(t, "snyk_token deleted", out)
		assert.Equal(t, `{"api":"a","b":"2","num":1.50}`, readFile(t, test.file))
	})

	t.Run("reports a missing key deleted and creates a missing file", func(t *testing.T) {
		test := newConfigTest(t)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_UNSET, "k")

		require.NoError(t, err)
		assert.Equal(t, "k deleted", out)
		assert.Equal(t, `{}`, readFile(t, test.file))
	})

	for name, args := range map[string][]string{"no key": nil, "an empty key": {""}} {
		t.Run("requires a key, given "+name, func(t *testing.T) {
			test := newConfigTest(t)
			writeFile(t, test.file, `{"a":"1"}`)

			_, err := test.invoke(t, WORKFLOWID_CONFIG_UNSET, args...)

			assertUsageError(t, err)
			assert.Equal(t, `{"a":"1"}`, readFile(t, test.file))
		})
	}

	t.Run("fails on invalid JSON and leaves the file untouched", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, `{"a":`)

		_, err := test.invoke(t, WORKFLOWID_CONFIG_UNSET, "a")

		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, `{"a":`, readFile(t, test.file))
	})

	t.Run("writes the file of the selected profile only", func(t *testing.T) {
		test, defaultFile := newProfileTest(t)
		writeFile(t, defaultFile, `{"a":"default"}`)
		writeFile(t, test.file, `{"a":"work","b":"2"}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_UNSET, "a")

		require.NoError(t, err)
		assert.Equal(t, "a deleted", out)
		assert.Equal(t, `{"b":"2"}`, readFile(t, test.file))
		assert.Equal(t, `{"a":"default"}`, readFile(t, defaultFile))
	})
}
