package envvars

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rs/zerolog"
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
		// Ensure we clean up the PATH back to how it was after the test.
		t.Setenv("PATH", os.Getenv("PATH"))

		dir := t.TempDir()
		uniqueEnvVarConfigFile, absEnvVarConfigFile := setupTestFile(t, "1", dir)
		uniqueEnvVarDotSnykEnv, absEnvVarDotSnykEnvFile := setupTestFile(t, ".snyk.env", dir)
		uniqueEnvVarDotEnvRc, absEnvVarDotEnvRcFile := setupTestFile(t, ".envrc", dir)

		files := []string{absEnvVarConfigFile, absEnvVarDotSnykEnvFile, absEnvVarDotEnvRcFile}
		currentDir, err := os.Getwd()
		require.NoError(t, err)
		err = os.Chdir(dir)
		require.NoError(t, err)

		// Don't allow Bash, so we skip the shell loading, it isn't relevant for this test.
		setShellAllowedForTest(t, "bash", false)

		LoadConfiguredEnvironment(files, dir)

		require.Equal(t, uniqueEnvVarConfigFile, os.Getenv(uniqueEnvVarConfigFile))
		require.Equal(t, uniqueEnvVarDotSnykEnv, os.Getenv(uniqueEnvVarDotSnykEnv))
		require.Equal(t, uniqueEnvVarDotEnvRc, os.Getenv(uniqueEnvVarDotEnvRc))

		err = os.Chdir(currentDir)
		require.NoError(t, err)
	})
}

func TestLoadConfiguredEnvironmentWithOptions(t *testing.T) {
	t.Run("should load custom config files", func(t *testing.T) {
		// Ensure we clean up the PATH back to how it was after the test.
		t.Setenv("PATH", os.Getenv("PATH"))

		dir := t.TempDir()
		uniqueEnvVar, absEnvVarConfigFile := setupTestFile(t, ".custom.env", dir)

		// Don't allow Bash, so we skip the shell loading, it isn't relevant for this test.
		setShellAllowedForTest(t, "bash", false)

		LoadConfiguredEnvironmentWithOptions(WithCustomConfigFiles([]string{absEnvVarConfigFile}))

		require.Equal(t, uniqueEnvVar, os.Getenv(uniqueEnvVar))
	})

	t.Run("should return early when context is canceled", func(t *testing.T) {
		// Ensure we clean up the PATH back to how it was after the test.
		t.Setenv("PATH", os.Getenv("PATH"))

		dir := t.TempDir()
		uniqueEnvVar, absEnvVarConfigFile := setupTestFile(t, ".custom.env", dir)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Don't allow Bash, so we skip the shell loading (although in theory we shouldn't hit it anyway), it isn't relevant for this test.
		setShellAllowedForTest(t, "bash", false)

		LoadConfiguredEnvironmentWithOptions(
			WithContext(ctx),
			WithCustomConfigFiles([]string{absEnvVarConfigFile}),
		)

		require.Empty(t, os.Getenv(uniqueEnvVar))
	})

	t.Run("should use the passed logger", func(t *testing.T) {
		// Ensure we clean up the PATH back to how it was after the test.
		t.Setenv("PATH", os.Getenv("PATH"))

		var logsBuffer bytes.Buffer
		logger := zerolog.New(&logsBuffer).Level(zerolog.DebugLevel)

		// Use a cancaled context so we skip the actual loading, it isn't relevant for this test.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// Don't allow Bash, so we skip the shell loading (although in theory we shouldn't hit it anyway), it isn't relevant for this test.
		setShellAllowedForTest(t, "bash", false)

		LoadConfiguredEnvironmentWithOptions(WithContext(ctx), WithLogger(&logger))

		require.NotEmpty(t, logsBuffer.String(), "Expected something to be logged.")
	})
}

func TestGetEnvFromShell(t *testing.T) {
	t.Run("should return empty for non-allowlisted shell", func(t *testing.T) {
		// Ensure we clean up the PATH back to how it was after the test.
		t.Setenv("PATH", os.Getenv("PATH"))

		logger := zerolog.Nop()

		env := getEnvFromShell(context.Background(), &logger, "not-allowlisted-shell")

		require.Empty(t, env)
	})
}

//nolint:unparam // Parameterized shell support keeps helper reusable when future tests need other allowlisted shells.
func setShellAllowedForTest(t *testing.T, shell string, allowed bool) {
	t.Helper()
	originalValue, hasOriginalValue := shellWhiteList[shell]
	shellWhiteList[shell] = allowed

	t.Cleanup(func() {
		if hasOriginalValue {
			shellWhiteList[shell] = originalValue
			return
		}

		delete(shellWhiteList, shell)
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
