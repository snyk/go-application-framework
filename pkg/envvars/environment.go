package envvars

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/subosito/gotenv"

	"github.com/snyk/go-application-framework/pkg/utils"
)

// Environment variable names
const (
	PathEnvVarName  = "PATH"
	ShellEnvVarName = "SHELL"
)

// GetCurrentEnvironment reads all current environment variables into a map.
func GetCurrentEnvironment() map[string]string {
	currentEnv := make(map[string]string)
	for _, envKeyValueString := range os.Environ() {
		envKeyValuePair := strings.SplitN(envKeyValueString, "=", 2)
		if len(envKeyValuePair) != 2 {
			continue
		}
		currentEnv[envKeyValuePair[0]] = envKeyValuePair[1]
	}
	return currentEnv
}

// SetEnvironmentDifferences Sets the environment variables that have changed since the current env snapshot.
func SetEnvironmentDifferences(currentEnv map[string]string, newEnv map[string]string) {
	for newEnvName, newEnvValue := range newEnv {
		if currentEnv[newEnvName] != newEnvValue {
			_ = os.Setenv(newEnvName, newEnvValue) // we can't do anything with the error
		}
	}
}

// LoadConfiguredEnvironment updates the environment with user and local configuration.
// First Bash's env is read (as a fallback), then the user's preferred SHELL's env is read, then the configuration files.
// The Bash env PATH is appended to the existing PATH (as a fallback), any other new PATH read is prepended (preferential).
// See LoadShellEnvironment and LoadConfigFiles.
func LoadConfiguredEnvironment(customConfigFiles []string, workingDirectory string) {
	currentEnv := GetCurrentEnvironment()
	newEnv := ReadShellEnvironment(currentEnv)
	newEnv = ReadConfigFiles(newEnv, customConfigFiles, workingDirectory)
	SetEnvironmentDifferences(currentEnv, newEnv)
}

// ReadShellEnvironment reads the user's shell environment with special handling of PATHs.
// First Bash's env is read (as a fallback), then the user's preferred SHELL's env is read.
// The Bash env PATH is appended to the existing PATH (as a fallback), the user's preferred SHELL's env PATH is prepended (preferential).
func ReadShellEnvironment(currentEnv map[string]string) map[string]string {
	bashEnvOutput := getEnvFromShell("bash")
	bashEnv := gotenv.Parse(strings.NewReader(bashEnvOutput))

	preferredShell, ok := bashEnv[ShellEnvVarName]
	if ok {
		preferredShellEnvOutput := getEnvFromShell(preferredShell)
		preferredShellEnv := gotenv.Parse(strings.NewReader(preferredShellEnvOutput))

		currentEnv = MergeEnvs(preferredShellEnv, currentEnv)
	}

	currentEnv = MergeEnvs(currentEnv, bashEnv)

	return currentEnv
}

var sdkVarNames = []string{"JAVA_HOME", "GOROOT"}

// ReadConfigFiles loads environment variables from configuration files.
// With special handling for PATH and SDK environment variables.
// The resultant PATH is constructed as follows:
// 1. Config file PATH entries (highest precedence)
// 2. SDK bin directories (if SDK variables like JAVA_HOME, GOROOT are set by the config file)
// 3. Previous PATH entries (lowest precedence)
func ReadConfigFiles(currentEnv map[string]string, customConfigFiles []string, workingDirectory string) map[string]string {
	for _, configFile := range customConfigFiles {
		if !filepath.IsAbs(configFile) {
			configFile = filepath.Join(workingDirectory, configFile)
		}

		configEnv, err := gotenv.Read(configFile)
		if err != nil {
			continue
		}

		// Check if SDK variables were set by this config file and append their bin directories
		for _, sdkVar := range sdkVarNames {
			if configEnvSDKValue, ok := configEnv[sdkVar]; ok {
				configEnv[PathEnvVarName] = MergePaths(configEnv[PathEnvVarName], filepath.Join(configEnvSDKValue, "bin"))
			}
		}

		currentEnv = MergeEnvs(configEnv, currentEnv)
	}

	return currentEnv
}

// guard against command injection
var shellWhiteList = map[string]bool{
	"bash":                   true,
	"/bin/zsh":               true,
	"/bin/sh":                true,
	"/bin/fish":              true,
	"/bin/csh":               true,
	"/bin/ksh":               true,
	"/bin/bash":              true,
	"/usr/bin/zsh":           true,
	"/usr/bin/sh":            true,
	"/usr/bin/fish":          true,
	"/usr/bin/csh":           true,
	"/usr/bin/ksh":           true,
	"/usr/bin/bash":          true,
	"/opt/homebrew/bin/bash": true,
}

func getEnvFromShell(shell string) string {
	// under windows, the shell environment is irrelevant
	if runtime.GOOS == "windows" {
		return ""
	}

	if !shellWhiteList[shell] {
		return ""
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()

	// deepcode ignore CommandInjection: false positive
	env, err := exec.CommandContext(ctx, shell, "--login", "-i", "-c", "printenv && exit").Output()
	if err != nil {
		return ""
	}

	return string(env)
}

// MergeEnvs merges two sets of environment variables, including PATHs.
func MergeEnvs(preferentialEnv map[string]string, leastPreferentialEnv map[string]string) map[string]string {
	mergedEnv := utils.MergeMaps(leastPreferentialEnv, preferentialEnv)
	mergedEnv[PathEnvVarName] = MergePaths(preferentialEnv[PathEnvVarName], leastPreferentialEnv[PathEnvVarName])
	return mergedEnv
}

// UpdatePath prepends or appends the extension to the current path.
// For append, if the entry is already there, it will not be re-added / moved.
// For prepend, if the entry is already there, it will be correctly re-prioritized to the front.
// The result is set into the process environment with os.Setenv.
//
//	pathExtension string the path component to be added.
//	prepend bool whether to pre- or append
func UpdatePath(pathExtension string, prepend bool) string {
	currentPath := os.Getenv(PathEnvVarName)
	var newPath string
	if prepend {
		newPath = MergePaths(pathExtension, currentPath)
	} else {
		newPath = MergePaths(currentPath, pathExtension)
	}
	_ = os.Setenv(PathEnvVarName, newPath)
	return newPath
}

// MergePaths appends the leastPreferentialPath to the preferentialPath while removing duplicates.
func MergePaths(preferentialPath string, leastPreferentialPath string) string {
	preferentialPathEntries := strings.Split(preferentialPath, string(os.PathListSeparator))
	leastPreferentialPathEntries := strings.Split(leastPreferentialPath, string(os.PathListSeparator))

	combinedSliceWithDuplicates := append(preferentialPathEntries, leastPreferentialPathEntries...)

	newPathSlice := utils.DedupeWithoutBlanks(combinedSliceWithDuplicates)

	newPath := strings.Join(newPathSlice, string(os.PathListSeparator))
	return newPath
}
