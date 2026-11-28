package config_workflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// configTest is an initialized engine whose default configuration file lives in a temporary home directory. config is
// the configuration the command line sets the positional arguments on: the engine's, or the one of the selected profile.
type configTest struct {
	engine workflow.Engine
	config configuration.Configuration
	file   string
}

// newConfigTest configures the engine as the CLI does, including the alternative key that maps snyk_token to api.
func newConfigTest(t *testing.T) *configTest {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	config := configuration.NewWithOpts(
		configuration.WithFiles("snyk"),
		configuration.WithSupportedEnvVars("XDG_CONFIG_HOME"),
		configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_", "test_"),
	)
	config.AddAlternativeKeys(configuration.AUTHENTICATION_TOKEN, []string{"snyk_cfg_api", "api"})
	// the application engine defaults INPUT_DIRECTORY to the working directory
	config.AddDefaultValue(configuration.INPUT_DIRECTORY, configuration.StandardDefaultValueFunction([]string{t.TempDir()}))
	engine := workflow.NewWorkFlowEngine(config)
	require.NoError(t, InitConfigWorkflows(engine))
	require.NoError(t, engine.Init())
	return &configTest{engine: engine, config: config, file: filepath.Join(home, ".config", "configstore", "snyk.json")}
}

// newProfileTest selects the profile "work", whose file is returned as file. defaultFile is the default file.
func newProfileTest(t *testing.T) (test *configTest, defaultFile string) {
	t.Helper()
	test = newConfigTest(t)
	dir := t.TempDir()
	test.config.Set(profile.DirKey, dir)
	test.config.Set(profile.ConfigKey, "work")
	registry, err := workflow.GetProfileRegistry(test.engine)
	require.NoError(t, err)
	p, err := registry.Profile("work")
	require.NoError(t, err)
	defaultFile, test.config, test.file = test.file, p.Configuration(), filepath.Join(dir, "work.json")
	return test, defaultFile
}

func (c *configTest) invoke(t *testing.T, id workflow.Identifier, args ...string) (string, error) {
	t.Helper()
	if len(args) > 0 {
		c.config.Set(configuration.INPUT_DIRECTORY, args)
	}
	output, err := c.engine.Invoke(id)
	if len(output) == 0 {
		return "", err
	}
	require.Len(t, output, 1)
	assert.Equal(t, "text/plain", output[0].GetContentType())
	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok)
	require.NotEmpty(t, payload, "empty output returns no data, so nothing is printed")
	return string(payload), err
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

// assertUsageError checks the error is the catalog's usage error and holds none of the texts of a cobra parse error.
func assertUsageError(t *testing.T, err error) {
	t.Helper()
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, "SNYK-CLI-0007", catalogErr.ErrorCode)
	for _, text := range []string{"unknown command", "unknown flag", "flag needs", "invalid argument"} {
		assert.NotContains(t, strings.ToLower(err.Error()), text)
		assert.NotContains(t, strings.ToLower(catalogErr.Detail), text)
	}
}

func Test_ConfigGet(t *testing.T) {
	const seed = `{"a":"1","num":1.50,"some-key":"x y","snyk_token":"t","api":"a-token","empty":""}`

	t.Run("prints the stored value", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, seed)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_GET, "a")

		require.NoError(t, err)
		assert.Equal(t, "1", out)
	})

	t.Run("keeps the text of a number", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, seed)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_GET, "num")

		require.NoError(t, err)
		assert.Equal(t, "1.50", out)
	})

	t.Run("reads the key as typed, not through alternative keys", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, seed)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_GET, "snyk_token")

		require.NoError(t, err)
		assert.Equal(t, "t", out)
	})

	for _, key := range []string{"nope", "empty"} {
		t.Run("prints nothing for "+key, func(t *testing.T) {
			test := newConfigTest(t)
			writeFile(t, test.file, seed)

			out, err := test.invoke(t, WORKFLOWID_CONFIG_GET, key)

			require.NoError(t, err)
			assert.Empty(t, out)
		})
	}

	t.Run("prints nothing without a file", func(t *testing.T) {
		test := newConfigTest(t)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_GET, "a")

		require.NoError(t, err)
		assert.Empty(t, out)
		assert.NoFileExists(t, test.file)
	})

	t.Run("prefers a non-empty SNYK_CFG_ variable over the file", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, seed)
		t.Setenv("SNYK_CFG_SOME_KEY", "from-env")
		t.Setenv("SNYK_CFG_NEW_KEY", "new-from-env")

		out, err := test.invoke(t, WORKFLOWID_CONFIG_GET, "some-key")
		require.NoError(t, err)
		assert.Equal(t, "from-env", out)

		out, err = test.invoke(t, WORKFLOWID_CONFIG_GET, "new-key")
		require.NoError(t, err)
		assert.Equal(t, "new-from-env", out)
	})

	t.Run("ignores an empty SNYK_CFG_ variable", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, seed)
		t.Setenv("SNYK_CFG_A", "")

		out, err := test.invoke(t, WORKFLOWID_CONFIG_GET, "a")

		require.NoError(t, err)
		assert.Equal(t, "1", out)
	})

	for name, args := range map[string][]string{"no key": nil, "an empty key": {""}} {
		t.Run("requires a key, given "+name, func(t *testing.T) {
			test := newConfigTest(t)
			writeFile(t, test.file, seed)

			_, err := test.invoke(t, WORKFLOWID_CONFIG_GET, args...)

			assertUsageError(t, err)
		})
	}

	t.Run("fails on invalid JSON and leaves the file untouched", func(t *testing.T) {
		test := newConfigTest(t)
		writeFile(t, test.file, `{"a":`)

		_, err := test.invoke(t, WORKFLOWID_CONFIG_GET, "a")

		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, `{"a":`, readFile(t, test.file))
	})

	t.Run("reads the file of the selected profile", func(t *testing.T) {
		test, defaultFile := newProfileTest(t)
		writeFile(t, defaultFile, `{"a":"default"}`)
		writeFile(t, test.file, `{"a":"work"}`)

		out, err := test.invoke(t, WORKFLOWID_CONFIG_GET, "a")

		require.NoError(t, err)
		assert.Equal(t, "work", out)
	})
}
