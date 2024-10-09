package configuration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/subosito/gotenv"
)

// LoadConfiguredEnvironment updates the environment with local configuration. Precedence as follows:
//  1. std folder-based config files
//  2. given command-line parameter config file
//  3. std config file in home directory
//  4. global shell configuration
func LoadConfiguredEnvironment(config Configuration) {
	bashOutput := getEnvFromShell("bash")

	// this is applied at the end always, as it does not overwrite existing variables
	defer func() { _ = gotenv.Apply(strings.NewReader(bashOutput)) }() //nolint:errcheck // we can't do anything with the error

	env := gotenv.Parse(strings.NewReader(bashOutput))
	specificShell, ok := env["SHELL"]
	if ok {
		fromSpecificShell := getEnvFromShell(specificShell)
		_ = gotenv.Apply(strings.NewReader(fromSpecificShell)) //nolint:errcheck // we can't do anything with the error
	}

	// process config files
	for _, file := range config.GetStringSlice(CUSTOM_CONFIG_FILES) {
		if !filepath.IsAbs(file) {
			file = filepath.Join(config.GetString(WORKING_DIRECTORY), file)
		}
		loadFile(file)
	}
}

func loadFile(fileName string) {
	// preserve path
	path := os.Getenv("PATH")

	// overwrite existing variables with file config
	err := gotenv.OverLoad(fileName)
	if err != nil {
		return
	}

	// add previous path to the end of the new
	UpdatePath(path, false)
}

// guard against command injection
var shellWhiteList = map[string]bool{
	"bash":          true,
	"/bin/zsh":      true,
	"/bin/sh":       true,
	"/bin/fish":     true,
	"/bin/csh":      true,
	"/bin/ksh":      true,
	"/bin/bash":     true,
	"/usr/bin/zsh":  true,
	"/usr/bin/sh":   true,
	"/usr/bin/fish": true,
	"/usr/bin/csh":  true,
	"/usr/bin/ksh":  true,
	"/usr/bin/bash": true,
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

// UpdatePath prepends or appends the extension to the current path. If the entry is already there, it skips it. The
// result is set into the process environment with os.Setenv.
//
//	pathExtension string the path component to be added.
//	prepend bool whether to pre- or append
func UpdatePath(pathExtension string, prepend bool) string {
	pathVarName := "PATH"

	if pathExtension == "" {
		return os.Getenv(pathVarName)
	}

	currentPath := os.Getenv(pathVarName)
	currentPathEntries := strings.Split(currentPath, string(os.PathListSeparator))

	pathEntries := map[string]bool{}
	for _, entry := range currentPathEntries {
		pathEntries[entry] = true
	}

	addPathEntries := strings.Split(pathExtension, string(os.PathListSeparator))
	var newPathSlice []string
	for _, entry := range addPathEntries {
		if !pathEntries[entry] {
			newPathSlice = append(newPathSlice, entry)
		}
	}

	resultSlice := append(newPathSlice, currentPathEntries...)
	if !prepend {
		resultSlice = append(currentPathEntries, newPathSlice...)
	}
	newPath := strings.Join(resultSlice, string(os.PathListSeparator))
	_ = os.Setenv(pathVarName, newPath)
	return newPath
}
