package configuration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
	parsedEnv := getParsedEnvFromShell("bash")
	shell := parsedEnv["SHELL"]
	fromSpecificShell := getParsedEnvFromShell(shell)

	if len(fromSpecificShell) > 0 {
		SetParsedVariablesToEnv(fromSpecificShell, false)
	} else {
		SetParsedVariablesToEnv(parsedEnv, false)
	}

	for _, file := range config.GetStringSlice(CUSTOM_CONFIG_FILES) {
		if !filepath.IsAbs(file) {
			file = filepath.Join(config.GetString(WORKING_DIRECTORY), file)
		}
		loadFile(file)
	}
}

func loadFile(fileName string) {
	file, err := os.Open(fileName)
	if err != nil {
		return
	}
	defer func(file *os.File) { _ = file.Close() }(file)
	env := gotenv.Parse(file)

	// we want these settings to overwrite existing settings (apart from the path)
	SetParsedVariablesToEnv(env, true)
}

func SetParsedVariablesToEnv(env gotenv.Env, replaceVars bool) {
	for k, v := range env {
		if k == "PATH" {
			UpdatePath(v)
			continue
		}

		_, exists := os.LookupEnv(k)
		if !exists || replaceVars {
			_ = os.Setenv(k, v)
		}
	}
}

func getParsedEnvFromShell(shell string) gotenv.Env {
	// guard against command injection
	var shellWhiteList = map[string]bool{
		"bash":      true,
		"/bin/zsh":  true,
		"/bin/sh":   true,
		"/bin/fish": true,
		"/bin/csh":  true,
		"/bin/ksh":  true,
		"/bin/bash": true,
	}

	if !shellWhiteList[shell] {
		return gotenv.Env{}
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFunc()

	env, err := exec.CommandContext(ctx, shell, "--login", "-i", "-c", "printenv && exit").Output()

	if err != nil {
		return gotenv.Env{}
	}
	parsedEnv := gotenv.Parse(strings.NewReader(string(env)))
	return parsedEnv
}

// UpdatePath prepends the extension to the current path. If the entry is already there, it skips it. The
// result is set into the process environment with os.Setenv.
func UpdatePath(pathExtension string) string {
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

	newPathSlice = append(newPathSlice, currentPathEntries...)
	newPath := strings.Join(newPathSlice, string(os.PathListSeparator))
	_ = os.Setenv(pathVarName, newPath)
	return newPath
}
