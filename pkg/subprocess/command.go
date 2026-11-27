package subprocess

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type config struct {
	dir     string
	snykEnv bool
}

// Option configures the command built by Command.
type Option func(*config)

// WithPWD sets the working directory and the matching PWD.
func WithPWD(dir string) Option {
	return func(c *config) {
		c.dir = dir
	}
}

// WithSnykEnv keeps SNYK_ variables for Snyk's own binaries, such as the snyk CLI. It still removes PWD.
func WithSnykEnv() Option {
	return func(c *config) {
		c.snykEnv = true
	}
}

// Command returns an unstarted exec.Cmd for name with args. Its environment has no SNYK_ variables
// unless WithSnykEnv is given, and no PWD, so no stale PWD is left. WithPWD sets it.
// The process environment is not changed.
func Command(ctx context.Context, name string, args []string, opts ...Option) *exec.Cmd {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = cfg.dir

	env := os.Environ()
	if !cfg.snykEnv {
		env = cleanEnv(env)
	}
	env = withoutPWD(env)
	if cfg.dir != "" && runtime.GOOS != "windows" && runtime.GOOS != "plan9" {
		if abs, err := filepath.Abs(cfg.dir); err == nil {
			env = append(env, "PWD="+abs)
		}
	}
	cmd.Env = env
	return cmd
}
