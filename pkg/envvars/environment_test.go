package envvars

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

	t.Run("should load non-SNYK_-prefixed allow-listed variables (e.g. JAVA_HOME)", func(t *testing.T) {
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
	allowed := []string{"PATH", "Path", "JAVA_HOME", "HTTP_PROXY", "https_proxy", "ALL_PROXY", "NO_PROXY", "SNYK_LOG_LEVEL", "SNYK_INTEGRATION_NAME"}
	for _, name := range allowed {
		t.Run(name+" is allowed", func(t *testing.T) {
			require.True(t, isAllowedEnvVarName(name))
		})
	}

	disallowed := []string{
		"HOME", "SHELL", "BASH_ENV", "ENV", "LD_PRELOAD", "RANDOM_VAR",
		// SNYK_-prefixed, but security-critical: must remain denied despite the SNYK_ prefix allow-list.
		"SNYK_TOKEN", "SNYK_OAUTH_TOKEN", "SNYK_DOCKER_TOKEN", "SNYK_API",
		"SNYK_REGISTRY_USERNAME", "SNYK_REGISTRY_PASSWORD", "SNYK_CFG_ORG", "SNYK_CFG_API",
	}
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
			// leave shellEnvOnce "consumed" (matching real single-process semantics), rather than reset
			// to zero, so a later test in this package cannot unexpectedly spawn a real shell again.
			shellEnvOnce.Do(func() {})
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

	t.Run("a HOME poisoned by a config file must not redirect a later shell invocation (regression, IDE-2136)", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("bash --login is not spawned on windows, see getEnvFromShell")
		}
		if _, err := exec.LookPath("bash"); err != nil {
			t.Skip("bash is not available")
		}

		originalHome := os.Getenv("HOME")
		t.Setenv("HOME", originalHome)
		t.Cleanup(func() { shellEnvOnce.Do(func() {}) })
		shellEnvOnce = sync.Once{}

		// consume the shellEnvOnce guard with the real HOME, exactly like the first scan of a
		// workspace, before any config file has been loaded.
		LoadConfiguredEnvironment(nil, t.TempDir())

		// an attacker-controlled workspace directory containing a malicious .bash_profile, matching
		// the PoC attached to IDE-2136.
		evilHome := t.TempDir()
		sentinel := filepath.Join(evilHome, "PWNED")
		bashProfile := fmt.Sprintf("#!/bin/sh\ntouch %s\n", sentinel)
		require.NoError(t, os.WriteFile(filepath.Join(evilHome, ".bash_profile"), []byte(bashProfile), 0700))

		configDir := t.TempDir()
		snykEnvFile := filepath.Join(configDir, ".snyk.env")
		require.NoError(t, os.WriteFile(snykEnvFile, []byte(fmt.Sprintf("HOME=%s\n", evilHome)), 0660))

		// a subsequent scan: loads the malicious .snyk.env (poisoning HOME), then would - without the
		// shellEnvOnce guard - spawn `bash --login`, sourcing the attacker's .bash_profile.
		LoadConfiguredEnvironment([]string{snykEnvFile}, configDir)

		require.NoFileExists(t, sentinel, "a config-file-poisoned HOME must never cause bash --login to source an attacker-controlled profile")
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
