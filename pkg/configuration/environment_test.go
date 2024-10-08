package configuration

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/subosito/gotenv"
)

var pathListSep = string(os.PathListSeparator)

func TestUpdatePathWithDefaults(t *testing.T) {
	t.Run("add to path from environment", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("b")

		require.Equal(t, "b"+pathListSep+pathFromEnv, os.Getenv("PATH"))
	})

	t.Run("add to path from environment only once", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("b")
		UpdatePath("b")

		require.Equal(t, "b"+pathListSep+pathFromEnv, os.Getenv("PATH"))
	})

	t.Run("add to path from environment only if not blank", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("")

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

		configuration := NewInMemory()
		configuration.Set(CUSTOM_CONFIG_FILES, []string{absEnvVarConfigFile, absEnvVarDotSnykEnvFile, absEnvVarDotEnvRcFile})

		err := os.Chdir(dir)
		require.NoError(t, err)

		LoadConfiguredEnvironment(configuration)

		require.Equal(t, uniqueEnvVarConfigFile, os.Getenv(uniqueEnvVarConfigFile))
		require.Equal(t, uniqueEnvVarDotSnykEnv, os.Getenv(uniqueEnvVarDotSnykEnv))
		require.Equal(t, uniqueEnvVarDotEnvRc, os.Getenv(uniqueEnvVarDotEnvRc))
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

func TestSetParsedVariablesToEnv(t *testing.T) {
	additionalEnv := gotenv.Env{}

	t.Run("add to path from environment", func(t *testing.T) {
		t.Setenv("a", "old")
		t.Setenv("PATH", "abc")
		additionalEnv["PATH"] = "b"
		additionalEnv["a"] = "new"

		SetParsedVariablesToEnv(additionalEnv, false)

		require.Equal(t, "b"+pathListSep+"abc", os.Getenv("PATH"))
		require.Equal(t, "old", os.Getenv("a"))
	})

	t.Run("replace vars, but path not", func(t *testing.T) {
		t.Setenv("a", "old")
		t.Setenv("PATH", "abc")
		additionalEnv["PATH"] = "b"
		additionalEnv["a"] = "new"

		SetParsedVariablesToEnv(additionalEnv, true)

		require.Equal(t, "b"+pathListSep+"abc", os.Getenv("PATH"))
		require.Equal(t, "new", os.Getenv("a"))
	})

	t.Run("add variables to env if not existent", func(t *testing.T) {
		newEnvVar := uuid.New().String()
		additionalEnv[newEnvVar] = "abc"

		SetParsedVariablesToEnv(additionalEnv, false)

		require.Equal(t, "abc", os.Getenv(newEnvVar))
	})

	t.Run("skip variables if existent", func(t *testing.T) {
		newEnvVar := uuid.New().String()
		t.Setenv(newEnvVar, "old")
		additionalEnv[newEnvVar] = "abc"

		SetParsedVariablesToEnv(additionalEnv, false)

		require.Equal(t, "old", os.Getenv(newEnvVar))
	})
}
