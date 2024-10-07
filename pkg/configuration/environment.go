package configuration

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/subosito/gotenv"
)

func LoadShellEnvironment() {
	if runtime.GOOS == "windows" {
		return
	}
	parsedEnv := getParsedEnvFromShell("bash")
	shell := parsedEnv["SHELL"]
	fromSpecificShell := getParsedEnvFromShell(shell)

	if len(fromSpecificShell) > 0 {
		SetParsedVariablesToEnv(fromSpecificShell)
	} else {
		SetParsedVariablesToEnv(parsedEnv)
	}
}

func SetParsedVariablesToEnv(env gotenv.Env) {
	for k, v := range env {
		_, exists := os.LookupEnv(k)
		if !exists {
			_ = os.Setenv(k, v)
		} else {
			// add to path, don't ignore additional paths
			if k == "PATH" {
				UpdatePath(v)
			}
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

func UpdatePath(pathExtension string) {
	if pathExtension == "" {
		return
	}

	currentPath := os.Getenv("PATH")
	currentPathEntries := strings.Split(currentPath, string(os.PathListSeparator))

	pathEntries := map[string]bool{}
	for _, entry := range currentPathEntries {
		pathEntries[entry] = true
	}

	newPathEntries := strings.Split(pathExtension, string(os.PathListSeparator))

	for _, entry := range newPathEntries {
		if !pathEntries[entry] {
			currentPathEntries = append(currentPathEntries, entry)
		}
	}

	newPath := strings.Join(currentPathEntries, string(os.PathListSeparator))
	_ = os.Setenv("PATH", newPath)
}
