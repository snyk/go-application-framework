package config_workflow

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration/profile"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// setXDGConfigHome sets XDG_CONFIG_HOME to a new directory and returns the configuration file under it.
func setXDGConfigHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return filepath.Join(dir, "configstore", "snyk.json")
}

// assertReads checks that the listing and config.get both see want as the value of a.
func assertReads(t *testing.T, test *configTest, want string) {
	t.Helper()
	out, err := test.invoke(t, WORKFLOWID_CONFIG)
	require.NoError(t, err)
	assert.Equal(t, "a: "+want, out)

	out, err = test.invoke(t, WORKFLOWID_CONFIG_GET, "a")
	require.NoError(t, err)
	assert.Equal(t, want, out)
}

func Test_ConfigReads_XDGConfigHome(t *testing.T) {
	for _, name := range []string{"", profile.DefaultName} {
		t.Run(fmt.Sprintf("the default profile, selected as %q, reads $XDG_CONFIG_HOME/configstore/snyk.json", name), func(t *testing.T) {
			test := newConfigTest(t)
			test.config.Set(profile.ConfigKey, name)
			xdgFile := setXDGConfigHome(t)
			writeFile(t, test.file, `{"a":"home"}`)
			writeFile(t, xdgFile, `{"a":"xdg"}`)

			assertReads(t, test, "xdg")
		})
	}

	t.Run("an empty XDG_CONFIG_HOME reads the home file", func(t *testing.T) {
		test := newConfigTest(t)
		t.Setenv("XDG_CONFIG_HOME", "")
		writeFile(t, test.file, `{"a":"home"}`)

		assertReads(t, test, "home")
	})

	t.Run("a named profile reads its own file", func(t *testing.T) {
		test, defaultFile := newProfileTest(t)
		xdgFile := setXDGConfigHome(t)
		writeFile(t, defaultFile, `{"a":"home"}`)
		writeFile(t, xdgFile, `{"a":"xdg"}`)
		writeFile(t, test.file, `{"a":"work"}`)

		assertReads(t, test, "work")
	})
}

func Test_ConfigWrites_XDGConfigHome(t *testing.T) {
	const seed = `{"a":"old","b":"1"}`
	for id, tc := range map[workflow.Identifier]struct {
		args []string
		want string
	}{
		WORKFLOWID_CONFIG_SET:   {[]string{"a=new"}, `{"a":"new","b":"1"}`},
		WORKFLOWID_CONFIG_UNSET: {[]string{"a"}, `{"b":"1"}`},
		WORKFLOWID_CONFIG_CLEAR: {nil, `{}`},
	} {
		t.Run(id.Host+": the default profile writes $XDG_CONFIG_HOME/configstore/snyk.json under its lock", func(t *testing.T) {
			test := newConfigTest(t)
			xdgFile := setXDGConfigHome(t)
			writeFile(t, test.file, seed)
			writeFile(t, xdgFile, seed)

			_, err := test.invoke(t, id, tc.args...)

			require.NoError(t, err)
			assert.Equal(t, tc.want, readFile(t, xdgFile))
			assert.FileExists(t, xdgFile+".lock")
			assert.Equal(t, seed, readFile(t, test.file))
			assert.NoFileExists(t, test.file+".lock")
		})

		t.Run(id.Host+": an empty XDG_CONFIG_HOME writes the home file", func(t *testing.T) {
			test := newConfigTest(t)
			t.Setenv("XDG_CONFIG_HOME", "")
			writeFile(t, test.file, seed)

			_, err := test.invoke(t, id, tc.args...)

			require.NoError(t, err)
			assert.Equal(t, tc.want, readFile(t, test.file))
		})

		t.Run(id.Host+": a named profile writes its own file only", func(t *testing.T) {
			test, defaultFile := newProfileTest(t)
			xdgFile := setXDGConfigHome(t)
			writeFile(t, defaultFile, seed)
			writeFile(t, test.file, seed)

			_, err := test.invoke(t, id, tc.args...)

			require.NoError(t, err)
			assert.Equal(t, tc.want, readFile(t, test.file))
			assert.Equal(t, seed, readFile(t, defaultFile))
			assert.NoDirExists(t, filepath.Dir(xdgFile))
		})
	}
}
