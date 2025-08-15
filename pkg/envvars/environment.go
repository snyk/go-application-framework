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

// LoadConfiguredEnvironment updates the environment with local configuration.
// First the user's SHELL is read, then the configuration files.
// Any new PATH is prepended to the existing PATH.
// See LoadShellEnvironment and LoadConfigFiles.
func LoadConfiguredEnvironment(customConfigFiles []string, workingDirectory string) {
	LoadShellEnvironment()

	LoadConfigFiles(customConfigFiles, workingDirectory)
}

// LoadShellEnvironment loads the user's shell environment and prepends
// any PATH entries to the current PATH. This ensures shell PATH takes precedence.
func LoadShellEnvironment() {
	bashOutput := getEnvFromShell("bash")

	// Prepend the Bash PATH now, as it is low priority
	// We use the Bash shell env as well, since the more info scraping the better to help OSS scans
	env := gotenv.Parse(strings.NewReader(bashOutput))
	if val, ok := env[PathEnvVarName]; ok {
		UpdatePath(val, true)
	}

	// this is applied at the end always, as it does not overwrite existing variables
	// We use the Bash shell env as well, since the more info scraping the better to help OSS scans
	defer func() { _ = gotenv.Apply(strings.NewReader(bashOutput)) }() //nolint:errcheck // we can't do anything with the error

	env = gotenv.Parse(strings.NewReader(bashOutput))
	specificShell, ok := env[ShellEnvVarName]
	if ok {
		fromSpecificShell := getEnvFromShell(specificShell)
		_ = gotenv.Apply(strings.NewReader(fromSpecificShell)) //nolint:errcheck // we can't do anything with the error

		env = gotenv.Parse(strings.NewReader(fromSpecificShell))
		if val, ok := env[PathEnvVarName]; ok {
			UpdatePath(val, true)
		}
	}
}

// LoadConfigFiles loads configuration files and prepends any PATH entries
// to the current PATH. This ensures config file PATH takes precedence.
func LoadConfigFiles(customConfigFiles []string, workingDirectory string) {
	// process config files
	for _, file := range customConfigFiles {
		if !filepath.IsAbs(file) {
			file = filepath.Join(workingDirectory, file)
		}
		loadFile(file)
	}
}

func loadFile(fileName string) {
	// preserve path
	previousPath := os.Getenv(PathEnvVarName)

	// overwrite existing variables with file config
	err := gotenv.OverLoad(fileName)
	if err != nil {
		return
	}

	// add previous path to the end of the new
	UpdatePath(previousPath, false)
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
