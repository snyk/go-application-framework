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

// LoadConfiguredEnvironment updates the environment with user and local configuration.
// First Bash's env is read (as a fallback), then the user's preferred SHELL's env is read, then the configuration files.
// The Bash env PATH is appended to the existing PATH (as a fallback), any other new PATH read is prepended (preferential).
// See LoadShellEnvironment and LoadConfigFiles.
func LoadConfiguredEnvironment(customConfigFiles []string, workingDirectory string) {
	LoadShellEnvironment()

	LoadConfigFiles(customConfigFiles, workingDirectory)
}

// LoadShellEnvironment loads the user's shell environment with special handling of PATHs.
// First Bash's env is read (as a fallback), then the user's preferred SHELL's env is read.
// The Bash env PATH is appended to the existing PATH (as a fallback), the user's preferred SHELL's env PATH is prepended (preferential).
func LoadShellEnvironment() {
	bashEnvOutput := getEnvFromShell("bash")

	// We first append the Bash PATH as a fallback for if the user's SHELL's env fails to read / parse.
	// Note: We do this as the more info scraping the better to help ensure we can find binaries for OSS scans.
	bashEnv := gotenv.Parse(strings.NewReader(bashEnvOutput))
	if val, ok := bashEnv[PathEnvVarName]; ok {
		UpdatePath(val, false)
	}

	// this is applied at the end always, as we do not want it to overwrite existing variables from the user's preferred SHELL
	defer func() { _ = gotenv.Apply(strings.NewReader(bashEnvOutput)) }() //nolint:errcheck // we can't do anything with the error

	preferredShell, ok := bashEnv[ShellEnvVarName]
	if ok {
		preferredShellEnvOutput := getEnvFromShell(preferredShell)
		_ = gotenv.Apply(strings.NewReader(preferredShellEnvOutput)) //nolint:errcheck // we can't do anything with the error

		preferredShellEnv := gotenv.Parse(strings.NewReader(preferredShellEnvOutput))
		if val, ok := preferredShellEnv[PathEnvVarName]; ok {
			UpdatePath(val, true)
		}
	}
}

// LoadConfigFiles loads environment variables from configuration files.
// With special handling for PATH and SDK environment variables.
// The resultant PATH is constructed as follows:
// 1. Config file PATH entries (highest precedence)
// 2. SDK bin directories (if SDK variables like JAVA_HOME, GOROOT are set by the config file)
// 3. Previous PATH entries (lowest precedence)
func LoadConfigFiles(customConfigFiles []string, workingDirectory string) {
	// Capture current SDK environment variables and track their latest values
	sdkVarNames := []string{"JAVA_HOME", "GOROOT"}
	sdkValues := make(map[string]string)
	for _, sdkVar := range sdkVarNames {
		sdkValues[sdkVar] = os.Getenv(sdkVar)
		// Unset the env var so we can capture if the config file sets it.
		_ = os.Unsetenv(sdkVar)
	}

	// Process config files
	for _, envFilePath := range customConfigFiles {
		if !filepath.IsAbs(envFilePath) {
			envFilePath = filepath.Join(workingDirectory, envFilePath)
		}

		// Preserve original PATH and unset it to ensure correct precedence order.
		// Without unsetting, if the config file has no PATH, SDK bins will be appended to original PATH (wrong precedence).
		previousPath := os.Getenv(PathEnvVarName)
		_ = os.Unsetenv(PathEnvVarName)

		// overwrite existing variables with file config
		err := gotenv.OverLoad(envFilePath)
		if err != nil {
			// Restore PATH if config file loading failed.
			_ = os.Setenv(PathEnvVarName, previousPath)
			continue
		}

		// Check if SDK variables were set by this config file and append their bin directories
		for _, sdkVar := range sdkVarNames {
			currentValue := os.Getenv(sdkVar)
			if currentValue != "" {
				binPath := filepath.Join(currentValue, "bin")
				UpdatePath(binPath, false)
				// Update our tracking and unset for the next file
				sdkValues[sdkVar] = currentValue
				_ = os.Unsetenv(sdkVar)
			}
		}

		// Add previous PATH to the end of the new
		UpdatePath(previousPath, false)
	}

	// Set final SDK values (latest from config files, or original if not overridden)
	for _, sdkVar := range sdkVarNames {
		if sdkValues[sdkVar] != "" {
			_ = os.Setenv(sdkVar, sdkValues[sdkVar])
		}
	}
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

// UpdatePath prepends or appends the extension to the current path.
// For append, if the entry is already there, it will not be re-added / moved.
// For prepend, if the entry is already there, it will be correctly re-prioritized to the front.
// The result is set into the process environment with os.Setenv.
//
//	pathExtension string the path component to be added.
//	prepend bool whether to pre- or append
func UpdatePath(pathExtension string, prepend bool) string {
	currentPath := os.Getenv(PathEnvVarName)

	if pathExtension == "" {
		return currentPath
	}

	if currentPath == "" {
		_ = os.Setenv(PathEnvVarName, pathExtension)
		return pathExtension
	}

	currentPathEntries := strings.Split(currentPath, string(os.PathListSeparator))
	addPathEntries := strings.Split(pathExtension, string(os.PathListSeparator))

	var combinedSliceWithDuplicates []string
	if prepend {
		combinedSliceWithDuplicates = append(addPathEntries, currentPathEntries...)
	} else {
		combinedSliceWithDuplicates = append(currentPathEntries, addPathEntries...)
	}

	newPathSlice := utils.Dedupe(combinedSliceWithDuplicates)

	newPath := strings.Join(newPathSlice, string(os.PathListSeparator))
	_ = os.Setenv(PathEnvVarName, newPath)
	return newPath
}
