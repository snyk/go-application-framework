package utils

import (
	"context"
	"fmt"
	"path/filepath"

	gitignore "github.com/sabhiram/go-gitignore"
	ripgrep "github.com/snyk/go-ripgrep-gitignore/v2"
)

const fileFilterRipgrepEnabled = "internal_file_filter_ripgrep_enabled"

func (fw *FileFilter) exclusionPredicate(globs []string) func(string) bool {
	if !fw.config.GetBool(fileFilterRipgrepEnabled) {
		return gitignore.CompileIgnoreLines(globs...).MatchesPath
	}
	return fw.ripgrepExclusionPredicate(globs, buildRipgrepPredicate)
}

// The opt-in loop calls this predicate serially; a WASM matcher serializes calls internally.
func (fw *FileFilter) ripgrepExclusionPredicate(globs []string, build func([]string) (func(string) (bool, error), error)) func(string) bool {
	match, err := build(globs)
	if err != nil {
		fw.logger.Warn().Err(err).Msg("ripgrep matcher failed; falling back to existing file filtering")
		return gitignore.CompileIgnoreLines(globs...).MatchesPath
	}
	fw.logger.Debug().Msg("using ripgrep file filter matcher")
	var fallback func(string) bool
	return func(file string) bool {
		if fallback != nil {
			return fallback(file)
		}
		excluded, err := match(file)
		if err == nil {
			return excluded
		}
		fw.logger.Warn().Err(err).Msg("ripgrep matcher failed; falling back to existing file filtering")
		fallback = gitignore.CompileIgnoreLines(globs...).MatchesPath
		return fallback(file)
	}
}

func buildRipgrepPredicate(globs []string) (func(string) (bool, error), error) {
	ctx := context.Background()
	builder, err := ripgrep.NewGitignore(ctx)
	if err != nil {
		return nil, err
	}
	// shortcut: this PoC reuses GAF's flattened globs; scoped raw policies are required before general adoption.
	for _, glob := range globs {
		if glob == "**/.git/**" {
			// Ripgrep's trailing /** does not match a worktree's regular .git pointer file.
			err = builder.AddPattern(ctx, "**/.git")
			if err != nil {
				return nil, fmt.Errorf("compile ripgrep git metadata pattern: %w", err)
			}
		}
		err = builder.AddPattern(ctx, glob)
		if err != nil {
			return nil, fmt.Errorf("compile ripgrep pattern: %w", err)
		}
	}
	matcher, err := builder.BuildMatcher(ctx)
	if err != nil {
		return nil, err
	}
	return func(file string) (bool, error) {
		result, err := matcher.Match(ctx, filepath.ToSlash(file))
		return result == ripgrep.Match, err
	}, nil
}
