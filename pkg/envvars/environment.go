package envvars

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/subosito/gotenv"

	"github.com/snyk/go-application-framework/pkg/utils"
)

// Environment variable names
const (
	PathEnvVarName  = "PATH"
	ShellEnvVarName = "SHELL"
)

// shellEnvOnce guards loadShellEnvironment so the user's shell profile is only ever read once per
// process. This is a deliberate security control, see loadShellEnvironment for details.
var shellEnvOnce sync.Once

// shellEnvLoader is the function invoked (at most once per process) by LoadConfiguredEnvironment to
// read the user's shell environment. It is a variable, rather than a direct call, so tests can verify
// it only ever runs once.
var shellEnvLoader = loadShellEnvironment

// LoadConfiguredEnvironment updates the environment with user and local configuration.
// First Bash's env is read (as a fallback), then the user's preferred SHELL's env is read, then the configuration files.
// The Bash env PATH is appended to the existing PATH (as a fallback), any other new PATH read is prepended (preferential).
//
// Security note: customConfigFiles are typically config files (e.g. .snyk.env, .envrc) found in a
// (potentially untrusted) workspace. Only allow-listed variable names from those files are applied to
// the process environment, see loadFile/isAllowedEnvVarName, and the shell profile is only ever read
// once (before any config file is processed, and never again), see loadShellEnvironment. Both controls
// exist to prevent a malicious config file from repointing HOME (or similar) to redirect a later shell
// invocation into sourcing an attacker-controlled profile script.
func LoadConfiguredEnvironment(customConfigFiles []string, workingDirectory string) {
	shellEnvOnce.Do(shellEnvLoader)

	// process config files
	for _, file := range customConfigFiles {
		if !filepath.IsAbs(file) {
			file = filepath.Join(workingDirectory, file)
		}
		loadFile(file)
	}
}

// loadShellEnvironment reads the user's shell environment (bash as a fallback, then their preferred
// SHELL) via an interactive login shell, see getEnvFromShell, and applies it to the process environment.
//
// It must run before any (potentially untrusted) config file is loaded, and only once per process
// (enforced by shellEnvOnce in LoadConfiguredEnvironment): once a config file has been loaded, HOME (or
// other variables influencing shell startup) may have been changed by that file, and re-running this
// would spawn `bash --login`, sourcing a profile from whatever HOME points to now instead of the real
// user's profile - the root cause of the .snyk.env arbitrary code execution issue (IDE-2136).
func loadShellEnvironment() {
	bashOutput := getEnvFromShell("bash")

	// this is applied at the end always, as it does not overwrite existing variables
	defer func() { _ = gotenv.Apply(strings.NewReader(bashOutput)) }() //nolint:errcheck // we can't do anything with the error

	bashEnv := gotenv.Parse(strings.NewReader(bashOutput))

	if bashPATH, ok := bashEnv[PathEnvVarName]; ok {
		UpdatePath(bashPATH, false)
	}

	specificShell, ok := bashEnv[ShellEnvVarName]
	if ok {
		fromSpecificShell := getEnvFromShell(specificShell)
		_ = gotenv.Apply(strings.NewReader(fromSpecificShell)) //nolint:errcheck // we can't do anything with the error

		specificShellEnv := gotenv.Parse(strings.NewReader(fromSpecificShell))
		if specificShellPATH, ok := specificShellEnv[PathEnvVarName]; ok {
			UpdatePath(specificShellPATH, true)
		}
	}
}

// allowedEnvVarNames lists the exact environment variable names permitted to be set from a config file
// loaded by loadFile. See isAllowedEnvVarName for the security rationale.
var allowedEnvVarNames = map[string]bool{
	PathEnvVarName:        true,
	"JAVA_HOME":           true,
	"HTTP_PROXY":          true,
	"http_proxy":          true,
	"HTTPS_PROXY":         true,
	"https_proxy":         true,
	"NO_PROXY":            true,
	"no_proxy":            true,
	"NODE_EXTRA_CA_CERTS": true,
	"KRB5_CONFIG":         true,
	"KRB5CCNAME":          true,
}

// allowedEnvVarPrefixes lists environment variable name prefixes permitted to be set from a config
// file loaded by loadFile, in addition to allowedEnvVarNames. See isAllowedEnvVarName.
var allowedEnvVarPrefixes = []string{"SNYK_"}

// isAllowedEnvVarName reports whether a variable read from a workspace config file (e.g. .snyk.env,
// .envrc) may be applied to the process environment.
//
// Config files can live in an untrusted workspace directory, so they must not be able to set arbitrary
// variables. Previously any variable - including HOME - could be set this way; combined with
// loadShellEnvironment spawning `bash --login` (which sources $HOME/.bash_profile), this allowed
// arbitrary code execution (IDE-2136). Only variables genuinely needed by Snyk tooling (the SNYK_
// prefix) or well-known variables required by common build/proxy tooling are allowed through. This is
// a partial mitigation: some allowed variables (e.g. JAVA_HOME) could still be pointed at malicious
// executables, but the direct HOME/shell-profile vector is closed.
func isAllowedEnvVarName(name string) bool {
	if allowedEnvVarNames[name] {
		return true
	}

	for _, prefix := range allowedEnvVarPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

// loadFile applies allow-listed environment variables from a config file (e.g. .snyk.env, .envrc)
// found in a (potentially untrusted) workspace directory. See isAllowedEnvVarName for which variables
// are applied and why not all of them are.
func loadFile(fileName string) {
	// preserve path
	previousPath := os.Getenv(PathEnvVarName)

	fileEnv, err := gotenv.Read(fileName)
	if err != nil {
		return
	}

	for key, value := range fileEnv {
		if !isAllowedEnvVarName(key) {
			continue
		}
		_ = os.Setenv(key, value)
	}

	// add previous path to the end of the new
	UpdatePath(previousPath, false)
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

// getEnvFromShell spawns an interactive login shell to read the user's shell environment.
//
// Security note: `--login` causes the shell to source profile files (e.g. $HOME/.bash_profile) from
// whatever HOME currently points to. Only call this before any untrusted config file has been loaded
// into the process environment - see loadShellEnvironment - otherwise a poisoned HOME could redirect
// this to an attacker-controlled profile script (IDE-2136).
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
