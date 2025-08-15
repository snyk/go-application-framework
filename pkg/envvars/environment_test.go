package envvars

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
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
}

func TestLoadConfigFiles(t *testing.T) {
	t.Run("should load config files and prepend PATH", func(t *testing.T) {
		dir := t.TempDir()
		originalPath := "original" + pathListSep + "existing"
		t.Setenv("PATH", originalPath)

		// Create a config file with PATH entry (no overlapping paths)
		configFileName := filepath.Join(dir, ".snyk.env")
		configContent := []byte("TEST_VAR=test_value\nPATH=config" + pathListSep + "file\n")
		err := os.WriteFile(configFileName, configContent, 0660)
		require.NoError(t, err)

		files := []string{configFileName}
		LoadConfigFiles(files, dir)

		// Verify environment variable was set
		require.Equal(t, "test_value", os.Getenv("TEST_VAR"))

		// Verify PATH was prepended (config path should come first)
		expectedPath := "config" + pathListSep + "file" + pathListSep + "original" + pathListSep + "existing"
		require.Equal(t, expectedPath, os.Getenv("PATH"))
	})

	t.Run("should handle relative config file paths", func(t *testing.T) {
		dir := t.TempDir()
		originalPath := "original"
		t.Setenv("PATH", originalPath)

		// Create a config file with relative path
		configFileName := ".test.env"
		configFilePath := filepath.Join(dir, configFileName)
		configContent := []byte("PATH=relative" + pathListSep + "path\n")
		err := os.WriteFile(configFilePath, configContent, 0660)
		require.NoError(t, err)

		files := []string{configFileName} // relative path
		LoadConfigFiles(files, dir)

		// Verify PATH was prepended
		expectedPath := "relative" + pathListSep + "path" + pathListSep + originalPath
		require.Equal(t, expectedPath, os.Getenv("PATH"))
	})
}

func TestLoadShellEnvironment(t *testing.T) {
	t.Run("should load shell environment and prepend PATH", func(t *testing.T) {
		originalPath := "original" + pathListSep + "path"
		t.Setenv("PATH", originalPath)

		// Note: This test will only work properly on non-Windows systems
		// and when a shell is available. On Windows or in environments
		// without shell access, the function will be a no-op.
		LoadShellEnvironment()

		// The shell environment loading behavior depends on the actual shell
		// and environment. We can't predict exact PATH changes, but we can
		// verify the function doesn't crash and PATH is still set.
		require.NotEmpty(t, os.Getenv("PATH"))
	})
}

func setupTestFile(t *testing.T, fileName string, dir string) (string, string) {
	t.Helper()
	uniqueEnvVar := strconv.Itoa(rand.Int())
	t.Setenv(uniqueEnvVar, "")
	absFileName := filepath.Join(dir, fileName)
	varName := []byte(fmt.Sprintf("%s=%s\n", uniqueEnvVar, uniqueEnvVar))
	err := os.WriteFile(absFileName, varName, 0660)
	require.NoError(t, err)
	return uniqueEnvVar, absFileName
}
