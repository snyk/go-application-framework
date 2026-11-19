package config_workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ConfigClear(t *testing.T) {
	for name, content := range map[string]string{"a missing file": "", "a file": `{"a":"1","num":1.50}`, "invalid JSON": `{"a":`} {
		t.Run("empties "+name, func(t *testing.T) {
			test := newConfigTest(t)
			if content != "" {
				writeFile(t, test.file, content)
			}

			out, err := test.invoke(t, WORKFLOWID_CONFIG_CLEAR)

			require.NoError(t, err)
			assert.Equal(t, "config cleared", out)
			assert.Equal(t, `{}`, readFile(t, test.file))
		})
	}

	t.Run("empties the file of the selected profile only", func(t *testing.T) {
		test, defaultFile := newProfileTest(t)
		writeFile(t, defaultFile, `{"a":"default"}`)
		writeFile(t, test.file, `{"a":"work"}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_CLEAR)

		require.NoError(t, err)
		assert.Equal(t, "config cleared", out)
		assert.Equal(t, `{}`, readFile(t, test.file))
		assert.Equal(t, `{"a":"default"}`, readFile(t, defaultFile))
	})
}
