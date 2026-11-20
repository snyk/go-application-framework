package config_workflow

import (
	"context"
	"testing"
	"time"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
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

func Test_ConfigWrites_WaitForTheFileLockOfTheConfigurationsStorage(t *testing.T) {
	for id, args := range map[workflow.Identifier][]string{WORKFLOWID_CONFIG_SET: {"k=v"}, WORKFLOWID_CONFIG_UNSET: {"a"}, WORKFLOWID_CONFIG_CLEAR: nil} {
		t.Run(id.Host, func(t *testing.T) {
			test := newConfigTest(t)
			writeFile(t, test.file, `{"a":"1"}`)
			test.config.Set(configuration.INPUT_DIRECTORY, args)
			held := test.config.GetStorage()
			require.NoError(t, held.Lock(t.Context(), time.Millisecond))
			defer func() { require.NoError(t, held.Unlock()) }()
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()

			_, err := test.engine.Invoke(id, workflow.WithContext(ctx))

			var catalogErr snyk_errors.Error
			require.ErrorAs(t, err, &catalogErr)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Equal(t, `{"a":"1"}`, readFile(t, test.file))
		})
	}
}
