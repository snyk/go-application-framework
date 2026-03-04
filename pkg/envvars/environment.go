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

	"github.com/rs/zerolog"
	"github.com/subosito/gotenv"

	"github.com/snyk/go-application-framework/pkg/utils"
)

// Environment variable names
const (
	PathEnvVarName  = "PATH"
	ShellEnvVarName = "SHELL"
)

var mu sync.Mutex

//nolint:containedctx // This options struct is local to a single call and not stored beyond function execution.
type loadConfiguredEnvironmentOptions struct {
	ctx               context.Context
	customConfigFiles []string
	workingDirectory  string
	logger            *zerolog.Logger
}

type LoadConfiguredEnvironmentOptions func(opts *loadConfiguredEnvironmentOptions)

func WithContext(ctx context.Context) LoadConfiguredEnvironmentOptions {
	return func(opts *loadConfiguredEnvironmentOptions) {
		opts.ctx = ctx
	}
}

func WithCustomConfigFiles(customConfigFiles []string, workingDirectory string) LoadConfiguredEnvironmentOptions {
	return func(opts *loadConfiguredEnvironmentOptions) {
		opts.customConfigFiles = customConfigFiles
		opts.workingDirectory = workingDirectory
	}
}

func WithLogger(logger *zerolog.Logger) LoadConfiguredEnvironmentOptions {
	return func(opts *loadConfiguredEnvironmentOptions) {
		if logger == nil {
			return
		}
		opts.logger = logger
	}
}

// LoadConfiguredEnvironment updates the environment with user and local configuration.
// First Bash's env is read (as a fallback), then the user's preferred SHELL's env is read, then the configuration files.
// The Bash env PATH is appended to the existing PATH (as a fallback), any other new PATH read is prepended (preferential).
// Deprecated use LoadConfiguredEnvironmentWithOptions instead.
func LoadConfiguredEnvironment(customConfigFiles []string, workingDirectory string) {
	LoadConfiguredEnvironmentWithOptions(WithCustomConfigFiles(customConfigFiles, workingDirectory))
}

// LoadConfiguredEnvironmentWithOptions updates the environment with user and local configuration.
// First Bash's env is read (as a fallback), then the user's preferred SHELL's env is read, then the configuration files.
// The Bash env PATH is appended to the existing PATH (as a fallback), any other new PATH read is prepended (preferential).
func LoadConfiguredEnvironmentWithOptions(opts ...LoadConfiguredEnvironmentOptions) {
	options := loadConfiguredEnvironmentOptions{
		ctx:    context.Background(),
		logger: utils.Ptr(zerolog.Nop()),
	}
	for _, opt := range opts {
		opt(&options)
	}
	logger := options.logger.With().Str("method", "LoadConfiguredEnvironment").Logger()

	mu.Lock()
	defer func() {
		mu.Unlock()
		logger.Trace().Msg("Loaded configured environment")
	}()
	logger.Debug().Msg("Loading configured environment")

	// Check the context hasn't been canceled before loading the environment.
	if ctxErr := options.ctx.Err(); ctxErr != nil {
		return
	}

	bashOutput := getEnvFromShell(options.ctx, options.logger, "bash")

	// Check the context hadn't been canceled while loading the Bash environment.
	if ctxErr := options.ctx.Err(); ctxErr != nil {
		return
	}

	// this is applied at the end always, as it does not overwrite existing variables
	defer func() {
		applyErr := gotenv.Apply(strings.NewReader(bashOutput))
		if applyErr != nil {
			logger.Trace().Err(applyErr).Msg("Failed to apply environment variables from Bash")
		}
	}()

	bashEnv := gotenv.Parse(strings.NewReader(bashOutput))

	if bashPATH, ok := bashEnv[PathEnvVarName]; ok {
		UpdatePath(bashPATH, false)
	}

	specificShell, ok := bashEnv[ShellEnvVarName]
	if ok {
		fromSpecificShell := getEnvFromShell(options.ctx, options.logger, specificShell)

		// Check the context hadn't been canceled while loading the user's preferred shell environment.
		if ctxErr := options.ctx.Err(); ctxErr != nil {
			return
		}

		applyErr := gotenv.Apply(strings.NewReader(fromSpecificShell))
		if applyErr != nil {
			logger.Trace().Err(applyErr).Str("shell", specificShell).Msg("Failed to apply environment variables from the user's preferred shell")
		}

		specificShellEnv := gotenv.Parse(strings.NewReader(fromSpecificShell))
		if specificShellPATH, ok := specificShellEnv[PathEnvVarName]; ok {
			UpdatePath(specificShellPATH, true)
		}
	}

	// process config files
	for _, file := range options.customConfigFiles {
		if !filepath.IsAbs(file) {
			file = filepath.Join(options.workingDirectory, file)
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

func getEnvFromShell(ctx context.Context, logger *zerolog.Logger, shell string) string {
	funcLogger := logger.With().Str("method", "getEnvFromShell").Str("shell", shell).Logger()
	// under windows, the shell environment is irrelevant
	if runtime.GOOS == "windows" {
		return ""
	}

	if !shellWhiteList[shell] {
		return ""
	}

	ctx, cancelFunc := context.WithTimeout(ctx, 5*time.Second)
	defer cancelFunc()

	funcLogger.Trace().Msg("get env from shell")
	// deepcode ignore CommandInjection: false positive
	env, err := exec.CommandContext(ctx, shell, "--login", "-i", "-c", "printenv && exit").Output()
	if err != nil {
		funcLogger.Trace().Err(err).Msg("failed to get env from shell")
		return ""
	}
	funcLogger.Trace().Msg("got env from shell")

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
