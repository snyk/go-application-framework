package config_workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Config(t *testing.T) {
	t.Run("lists the keys sorted, masking INTERNAL_ values", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, `{"z":"v","a":"1","INTERNAL_OAUTH_TOKEN_STORAGE":"secret","internal_x":"s","api":"tok",`+
			`"oci-registry-password":"pw","num":1.50,"snyk_token":"t","zz":""}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG)

		require.NoError(t, err)
		assert.Equal(t, "INTERNAL_OAUTH_TOKEN_STORAGE: ***\na: 1\napi: tok\ninternal_x: ***\nnum: 1.50\n"+
			"oci-registry-password: pw\nsnyk_token: t\nz: v\nzz:", out)
	})

	t.Run("prints other values as JavaScript's String() does", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, `{"arr":[1,"x",null,[2,3]],"b":true,"n":null,"obj":{"k":"v"}}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG)

		require.NoError(t, err)
		assert.Equal(t, "arr: 1,x,,2,3\nb: true\nn: null\nobj: [object Object]", out)
	})

	for name, content := range map[string]string{"without a file": "", "for an empty object": "{}", "for a blank file": " \n"} {
		t.Run("prints nothing "+name, func(t *testing.T) {
			test := newConfigTest(t)
			if content != "" {
				writeFile(t, test.file, content)
			}

			out, err := test.invoke(t, WORKFLOWID_CONFIG)

			require.NoError(t, err)
			assert.Empty(t, out)
		})
	}

	t.Run("rejects an unknown subcommand", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, `{"a":"1"}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG, "bogus")

		assertUsageError(t, err)
		assert.Empty(t, out)
	})

	t.Run("lists the file of the selected profile only", func(t *testing.T) {
		test, defaultFile := newProfileTest(t)
		writeFile(t, defaultFile, `{"a":"default","d":"x"}`)
		writeFile(t, test.file, `{"a":"work"}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG)

		require.NoError(t, err)
		assert.Equal(t, "a: work", out)
		assert.Equal(t, `{"a":"default","d":"x"}`, readFile(t, defaultFile))
	})
}

func Test_fileStorage_KeepsKeysAsTypedAndNumbersAsWritten(t *testing.T) {
	setups := map[string]func(t *testing.T) *configTest{
		"default": newConfigTest,
		"profile": func(t *testing.T) *configTest {
			t.Helper()
			test, _ := newProfileTest(t)
			return test
		},
	}
	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			test := setup(t)
			writeFile(t, test.file, `{"num":1.50}`)

			storage, err := fileStorage(test.config)
			require.NoError(t, err)
			require.NoError(t, storage.Set("snyk_token", "x"))

			assert.Equal(t, `{"num":1.50,"snyk_token":"x"}`, readFile(t, test.file))
		})
	}
}
