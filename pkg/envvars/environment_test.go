package envvars

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestReadConfigFiles(t *testing.T) {
	t.Run("should load config files and prepend PATH", func(t *testing.T) {
		dir := t.TempDir()
		originalPathValue := "original_path"
		initialEnv := map[string]string{
			"PATH": originalPathValue,
		}

		// Create a config file with PATH entry
		configFileName := filepath.Join(dir, ".snyk.env")
		configContent := []byte("TEST_VAR=test_value\nPATH=config" + pathListSep + "file\n")
		err := os.WriteFile(configFileName, configContent, 0660)
		require.NoError(t, err)

		files := []string{configFileName}
		finalEnv := ReadConfigFiles(initialEnv, files, dir)

		// Verify environment variable was set
		require.Equal(t, "test_value", finalEnv["TEST_VAR"])

		// Verify PATH was prepended (config path should come first)
		expectedPath := "config" + pathListSep + "file" + pathListSep + originalPathValue
		require.Equal(t, expectedPath, finalEnv["PATH"])
	})

	t.Run("should handle relative config file paths", func(t *testing.T) {
		dir := t.TempDir()
		originalPathValue := "original_path"
		initialEnv := map[string]string{
			"PATH": originalPathValue,
		}

		// Create a config file with relative path
		configFileName := ".test.env"
		configFilePath := filepath.Join(dir, configFileName)
		configContent := []byte("PATH=relative" + pathListSep + "path\n")
		err := os.WriteFile(configFilePath, configContent, 0660)
		require.NoError(t, err)

		files := []string{configFileName} // relative path
		finalEnv := ReadConfigFiles(initialEnv, files, dir)

		// Verify PATH was prepended
		expectedPath := "relative" + pathListSep + "path" + pathListSep + originalPathValue
		require.Equal(t, expectedPath, finalEnv["PATH"])
	})

	t.Run("should add config file PATH and SDK bin directories to PATH (in that precedence order)", func(t *testing.T) {
		dir := t.TempDir()
		originalPathValue := "original_path"
		initialEnv := map[string]string{
			"PATH":      originalPathValue,
			"JAVA_HOME": "",
			"GOROOT":    "system_go",
		}

		// Create a config file that sets SDK variables and PATH
		configFileName := filepath.Join(dir, ".snyk.env")
		configFilePathValue := "config_bin"
		configFileJavaHomeValue := "project_java"
		configFileGoRootValue := "project_go"
		configContent := []byte("JAVA_HOME=" + configFileJavaHomeValue + "\nGOROOT=" + configFileGoRootValue + "\nPATH=" + configFilePathValue + "\n")
		err := os.WriteFile(configFileName, configContent, 0660)
		require.NoError(t, err)

		// Act
		finalEnv := ReadConfigFiles(initialEnv, []string{configFileName}, dir)

		// Verify SDK variables were set
		assert.Equal(t, "project_java", finalEnv["JAVA_HOME"])
		assert.Equal(t, "project_go", finalEnv["GOROOT"])

		// Verify PATH order: config PATH, then SDK bins, then original PATH
		// Build expected paths using platform-appropriate separators
		javaHomeBin := filepath.Join(configFileJavaHomeValue, "bin")
		goRootBin := filepath.Join(configFileGoRootValue, "bin")
		expectedPath := configFilePathValue + pathListSep + javaHomeBin + pathListSep + goRootBin + pathListSep + originalPathValue
		assert.Equal(t, expectedPath, finalEnv["PATH"])
	})

	t.Run("should not add SDK bin directories when SDK variables are pre-existing and not overridden", func(t *testing.T) {
		dir := t.TempDir()
		originalPathValue := "original_path"
		preExistingJavaHome := "system_java"
		preExistingGoRoot := "system_go"
		initialEnv := map[string]string{
			"PATH":      originalPathValue,
			"JAVA_HOME": preExistingJavaHome,
			"GOROOT":    preExistingGoRoot,
		}

		// Create a config file that doesn't change these SDK variables
		configFileName := filepath.Join(dir, ".snyk.env")
		configContent := []byte("OTHER_VAR=other_value\n")
		err := os.WriteFile(configFileName, configContent, 0660)
		require.NoError(t, err)

		// Act
		finalEnv := ReadConfigFiles(initialEnv, []string{configFileName}, dir)

		// Verify SDK variables are unchanged
		assert.Equal(t, preExistingJavaHome, finalEnv["JAVA_HOME"])
		assert.Equal(t, preExistingGoRoot, finalEnv["GOROOT"])

		// Verify PATH was not modified by SDK bin directories
		assert.Equal(t, originalPathValue, finalEnv["PATH"])
	})

	t.Run("should add bin directories only for SDK variables changed by config files", func(t *testing.T) {
		dir := t.TempDir()
		originalPathValue := "original_path"
		preExistingJavaHome := "system_java"
		initialEnv := map[string]string{
			"PATH":      originalPathValue,
			"JAVA_HOME": preExistingJavaHome,
		}

		// Create a config file that only changes GOROOT
		configFileName := filepath.Join(dir, ".snyk.env")
		configFileGoRootValue := "project_go"
		configContent := []byte("GOROOT=" + configFileGoRootValue + "\n")
		err := os.WriteFile(configFileName, configContent, 0660)
		require.NoError(t, err)

		// Act
		finalEnv := ReadConfigFiles(initialEnv, []string{configFileName}, dir)

		// Verify JAVA_HOME is unchanged, GOROOT is changed
		assert.Equal(t, preExistingJavaHome, finalEnv["JAVA_HOME"])
		assert.Equal(t, configFileGoRootValue, finalEnv["GOROOT"])

		// Verify only GOROOT/bin was added to PATH (appended after the config path, which is empty)
		// Build expected path using platform-appropriate separators
		goRootBin := filepath.Join(configFileGoRootValue, "bin")
		expectedPath := goRootBin + pathListSep + originalPathValue
		assert.Equal(t, expectedPath, finalEnv["PATH"])
	})

	t.Run("should re-prioritize SDK bin directories when config file sets same value", func(t *testing.T) {
		dir := t.TempDir()
		javaHomeValue := "project_java"
		javaHomeBinPath := filepath.Join(javaHomeValue, "bin")
		systemBin := "system_bin"
		usrBin := "usr_bin"
		originalPathValue := systemBin + pathListSep + javaHomeBinPath + pathListSep + usrBin
		initialEnv := map[string]string{
			"PATH":      originalPathValue,
			"JAVA_HOME": javaHomeValue,
		}

		// Create a config file that sets JAVA_HOME to the same value
		configFileName := filepath.Join(dir, ".snyk.env")
		configFilePathValue := "config_path"
		configContent := []byte("JAVA_HOME=" + javaHomeValue + "\nPATH=" + configFilePathValue + "\n")
		err := os.WriteFile(configFileName, configContent, 0660)
		require.NoError(t, err)

		// Act
		finalEnv := ReadConfigFiles(initialEnv, []string{configFileName}, dir)

		// Verify JAVA_HOME is still the same value
		assert.Equal(t, javaHomeValue, finalEnv["JAVA_HOME"])

		// Verify PATH re-prioritization: config PATH, then JAVA_HOME/bin, then the original PATH with JAVA_HOME/bin deduplicated out
		// Build expected path using platform-appropriate separators
		javaHomeBin := filepath.Join(javaHomeValue, "bin")
		expectedPath := configFilePathValue + pathListSep + javaHomeBin + pathListSep + systemBin + pathListSep + usrBin
		assert.Equal(t, expectedPath, finalEnv["PATH"])
	})
}

func TestReadShellEnvironment(t *testing.T) {
	t.Run("should read shell environment and still contain original PATH", func(t *testing.T) {
		originalPathValue := "original_path"
		initialEnv := map[string]string{
			"PATH": originalPathValue,
		}

		// Note: This test will only work properly on non-Windows systems
		// and when a shell is available. On Windows or in environments
		// without shell access, the function will be a no-op.
		finalEnv := ReadShellEnvironment(initialEnv)

		assert.Contains(t, finalEnv["PATH"], originalPathValue)
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
