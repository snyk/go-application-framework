package envvars

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var pathListSep = string(os.PathListSeparator)

func TestUpdatePathWithDefaults(t *testing.T) {
	t.Run("add to path from environment (prepend)", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("b", true)

		require.Equal(t, "b"+pathListSep+pathFromEnv, os.Getenv("PATH"))
	})

	t.Run("add to path from environment (append)", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("b", false)

		require.Equal(t, pathFromEnv+pathListSep+"b", os.Getenv("PATH"))
	})

	t.Run("add to path from environment only once (prepend)", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("b", true)
		UpdatePath("b", true)

		require.Equal(t, "b"+pathListSep+pathFromEnv, os.Getenv("PATH"))
	})

	t.Run("prepend re-prioritizes existing path segment to front", func(t *testing.T) {
		pathFromEnv := "a" + pathListSep + "b" + pathListSep + "c"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("b", true)

		require.Equal(t, "b"+pathListSep+"a"+pathListSep+"c", os.Getenv("PATH"))
	})

	t.Run("add multiple entries at once (prepend)", func(t *testing.T) {
		pathFromEnv := "d" + pathListSep + "e"
		t.Setenv("PATH", pathFromEnv)

		pathToPrepend := "a" + pathListSep + "b" + pathListSep + "c"
		UpdatePath(pathToPrepend, true)

		require.Equal(t, pathToPrepend+pathListSep+pathFromEnv, os.Getenv("PATH"))
	})

	t.Run("add multiple entries at once (append)", func(t *testing.T) {
		pathFromEnv := "a" + pathListSep + "b"
		t.Setenv("PATH", pathFromEnv)

		pathToAppend := "c" + pathListSep + "d" + pathListSep + "e"
		UpdatePath(pathToAppend, false)

		require.Equal(t, pathFromEnv+pathListSep+pathToAppend, os.Getenv("PATH"))
	})

	t.Run("add multiple entries with duplicates of existing entries (prepend)", func(t *testing.T) {
		pathFromEnv := "b" + pathListSep + "d"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("a"+pathListSep+"b"+pathListSep+"c", true)

		require.Equal(t, "a"+pathListSep+"b"+pathListSep+"c"+pathListSep+"d", os.Getenv("PATH"))
	})

	t.Run("add multiple entries with duplicates of existing entries (append)", func(t *testing.T) {
		pathFromEnv := "a" + pathListSep + "b" + pathListSep + "c"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("b"+pathListSep+"c"+pathListSep+"d", false)

		require.Equal(t, "a"+pathListSep+"b"+pathListSep+"c"+pathListSep+"d", os.Getenv("PATH"))
	})

	t.Run("add multiple entries with duplicates of new entries (prepend)", func(t *testing.T) {
		pathFromEnv := "b" + pathListSep + "d"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("a"+pathListSep+"b"+pathListSep+"c"+pathListSep+"b", true)

		require.Equal(t, "a"+pathListSep+"b"+pathListSep+"c"+pathListSep+"d", os.Getenv("PATH"))
	})

	t.Run("add multiple entries with duplicates of new entries (append)", func(t *testing.T) {
		pathFromEnv := "a" + pathListSep + "b" + pathListSep + "c"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("b"+pathListSep+"c"+pathListSep+"d"+pathListSep+"c", false)

		require.Equal(t, "a"+pathListSep+"b"+pathListSep+"c"+pathListSep+"d", os.Getenv("PATH"))
	})

	t.Run("add to path from environment only if not blank", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("", true)

		require.Equal(t, pathFromEnv, os.Getenv("PATH"))
	})
}

func TestLoadFile(t *testing.T) {
	t.Run("should load given config file", func(t *testing.T) {
		uniqueEnvVar, fileName := setupTestFile(t, "env-file", t.TempDir())

		loadFile(fileName)

		require.Equal(t, uniqueEnvVar, os.Getenv(uniqueEnvVar))
	})

	t.Run("should not load HOME or other non-allow-listed variables from the config file", func(t *testing.T) {
		dir := t.TempDir()
		fileName := filepath.Join(dir, "env-file")

		originalHome := os.Getenv("HOME")
		t.Setenv("HOME", originalHome)

		disallowedVar := "DISALLOWED_" + strconv.Itoa(rand.Int())
		t.Setenv(disallowedVar, "")

		contents := fmt.Sprintf("HOME=/tmp/evil-home\n%s=poisoned\n", disallowedVar)
		require.NoError(t, os.WriteFile(fileName, []byte(contents), 0660))

		loadFile(fileName)

		require.Equal(t, originalHome, os.Getenv("HOME"), "HOME must not be overwritten by a config file")
		require.Empty(t, os.Getenv(disallowedVar), "non-allow-listed variables must not be set from a config file")
	})

	t.Run("should load allow-listed variables other than SNYK_ prefixed ones", func(t *testing.T) {
		dir := t.TempDir()
		fileName := filepath.Join(dir, "env-file")

		t.Setenv("JAVA_HOME", "")

		contents := "JAVA_HOME=/opt/java\n"
		require.NoError(t, os.WriteFile(fileName, []byte(contents), 0660))

		loadFile(fileName)

		require.Equal(t, "/opt/java", os.Getenv("JAVA_HOME"))
	})
}

func TestIsAllowedEnvVarName(t *testing.T) {
	allowed := []string{"PATH", "JAVA_HOME", "HTTP_PROXY", "https_proxy", "NO_PROXY", "SNYK_TOKEN", "SNYK_CFG_ORG"}
	for _, name := range allowed {
		t.Run(name+" is allowed", func(t *testing.T) {
			require.True(t, isAllowedEnvVarName(name))
		})
	}

	disallowed := []string{"HOME", "SHELL", "BASH_ENV", "ENV", "LD_PRELOAD", "RANDOM_VAR"}
	for _, name := range disallowed {
		t.Run(name+" is not allowed", func(t *testing.T) {
			require.False(t, isAllowedEnvVarName(name))
		})
	}
}

func TestLoadConfiguredEnvironment(t *testing.T) {
	t.Run("should load default config files", func(t *testing.T) {
		dir := t.TempDir()
		uniqueEnvVarConfigFile, absEnvVarConfigFile := setupTestFile(t, "1", dir)
		uniqueEnvVarDotSnykEnv, absEnvVarDotSnykEnvFile := setupTestFile(t, ".snyk.env", dir)
		uniqueEnvVarDotEnvRc, absEnvVarDotEnvRcFile := setupTestFile(t, ".envrc", dir)

		files := []string{absEnvVarConfigFile, absEnvVarDotSnykEnvFile, absEnvVarDotEnvRcFile}
		currentDir, err := os.Getwd()
		require.NoError(t, err)
		err = os.Chdir(dir)
		require.NoError(t, err)

		LoadConfiguredEnvironment(files, dir)

		require.Equal(t, uniqueEnvVarConfigFile, os.Getenv(uniqueEnvVarConfigFile))
		require.Equal(t, uniqueEnvVarDotSnykEnv, os.Getenv(uniqueEnvVarDotSnykEnv))
		require.Equal(t, uniqueEnvVarDotEnvRc, os.Getenv(uniqueEnvVarDotEnvRc))

		err = os.Chdir(currentDir)
		require.NoError(t, err)
	})

	t.Run("should only read the shell environment once, even across multiple calls", func(t *testing.T) {
		originalLoader := shellEnvLoader
		t.Cleanup(func() {
			shellEnvOnce = sync.Once{}
			shellEnvLoader = originalLoader
		})
		shellEnvOnce = sync.Once{}

		var callCount int
		shellEnvLoader = func() { callCount++ }

		dir := t.TempDir()

		LoadConfiguredEnvironment(nil, dir)
		LoadConfiguredEnvironment(nil, dir)
		LoadConfiguredEnvironment(nil, dir)

		require.Equal(t, 1, callCount, "the shell environment must only be read once per process")
	})
}

// setupTestFile writes a config file containing a single, uniquely-named, allow-listed (SNYK_-prefixed)
// environment variable, and returns the variable name and the absolute path of the file written.
func setupTestFile(t *testing.T, fileName string, dir string) (string, string) {
	t.Helper()
	uniqueEnvVar := "SNYK_TEST_" + strconv.Itoa(rand.Int())
	t.Setenv(uniqueEnvVar, "")
	absFileName := filepath.Join(dir, fileName)
	varName := []byte(fmt.Sprintf("%s=%s\n", uniqueEnvVar, uniqueEnvVar))
	err := os.WriteFile(absFileName, varName, 0660)
	require.NoError(t, err)
	return uniqueEnvVar, absFileName
}
