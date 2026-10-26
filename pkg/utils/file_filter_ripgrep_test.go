package utils

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

func TestFileFilter_RipgrepExactFiles(t *testing.T) {
	fixture := gitTrackedFilesTestCase{
		files: map[string]string{
			"regular.ts": "", "tracked.log": "", "untracked.log": "",
			"nested/drop.ts": "", "nested/keep.ts": "",
			"vendor/tracked.ts": "", "vendor/secret.ts": "", "vendor/private.ts": "", "vendor/untracked.ts": "",
			"expired.ts": "", "code.ts": "", "secrets.ts": "",
		},
		trackedFiles: []string{"tracked.log", "vendor/tracked.ts", "vendor/secret.ts", "vendor/private.ts"},
		ruleFiles: map[string]string{
			".gitignore":        "*.log\nvendor/\n",
			"nested/.gitignore": "*.ts\n!keep.ts\n",
			".dcignore":         "vendor/private.ts\n",
			".snyk":             "exclude:\n  global:\n    - vendor/secret.ts\n    - expired.ts:\n        expires: '2000-01-01'\n  code:\n    - code.ts\n  secrets:\n    - secrets.ts\n",
		},
	}
	root, _ := setupGitTrackedFilesTestCase(t, fixture)
	for _, meta := range []bool{false, true} {
		for _, tracked := range []bool{false, true} {
			for _, section := range []DotSnykExcludeSectionName{DotSnykExcludeCode, DotSnykExcludeSecrets} {
				t.Run(fmt.Sprintf("meta=%t/tracked=%t/section=%s", meta, tracked, section), func(t *testing.T) {
					want := []string{".gitignore", ".dcignore", ".snyk", "nested/.gitignore", "nested/keep.ts", "regular.ts", "expired.ts"}
					if section == DotSnykExcludeCode {
						want = append(want, "secrets.ts")
					} else {
						want = append(want, "code.ts")
					}
					if tracked {
						want = append(want, "tracked.log", "vendor/tracked.ts")
					}
					for _, enabled := range []bool{false, true} {
						config := newTestConfig(map[string]bool{
							FF_FILE_FILTER_METACHARACTER_FIX: meta, FF_GITIGNORE_RESPECT_TRACKED_FILES: tracked,
							fileFilterRipgrepEnabled: enabled,
						})
						var logs bytes.Buffer
						logger := zerolog.New(&logs)
						filter := NewFileFilter(root, &logger, WithConfig(config), WithDotSnykSections([]DotSnykExcludeSectionName{DotSnykExcludeGlobal, section}))
						rules, err := filter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
						require.NoError(t, err)
						require.ElementsMatch(t, want, ripgrepFilteredPaths(t, filter, root, rules), "ripgrep=%t", enabled)
						require.NotContains(t, logs.String(), "falling back")
						require.Equal(t, enabled, strings.Contains(logs.String(), "using ripgrep file filter matcher"))
					}
				})
			}
		}
	}
}

func TestFileFilter_RipgrepMetacharactersAndPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "project (old)+$")
	for _, p := range []string{"build (old)/drop.ts", "src/a.ts", "src/keep.ts"} {
		createFileInPath(t, filepath.Join(root, p), nil)
	}
	createFileInPath(t, filepath.Join(root, ".gitignore"), []byte("build (old)/\nsrc/*.ts\n!src/keep.ts\n"))
	for _, enabled := range []bool{false, true} {
		config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true, fileFilterRipgrepEnabled: enabled})
		filter := NewFileFilter(root, &log.Logger, WithConfig(config))
		rules, err := filter.GetRules([]string{".gitignore"})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{".gitignore", "src/keep.ts"}, ripgrepFilteredPaths(t, filter, root, rules))
		for _, input := range []string{"relative/file.ts", filepath.Join(root, "file.ts"), filepath.ToSlash(filepath.Join(root, "file.ts"))} {
			in := make(chan string, 1)
			in <- input
			close(in)
			var got []string
			for file := range filter.GetFilteredFiles(in, nil) {
				got = append(got, file)
			}
			require.Equal(t, []string{input}, got, "empty rules, ripgrep=%t", enabled)
		}
	}
	filter := NewFileFilter(root, &log.Logger)
	require.False(t, filter.config.GetBool(fileFilterRipgrepEnabled), "PoC must remain opt-in")
}

func TestFileFilter_RipgrepFallback(t *testing.T) {
	for _, stage := range []string{"build", "match", "success"} {
		t.Run(stage, func(t *testing.T) {
			var logs bytes.Buffer
			logger := zerolog.New(&logs)
			filter := NewFileFilter(".", &logger)
			calls := 0
			predicate := filter.ripgrepExclusionPredicate([]string{"*.log"}, func(globs []string) (func(string) (bool, error), error) {
				require.Equal(t, []string{"*.log"}, globs)
				if stage == "build" {
					return nil, errors.New("build failure")
				}
				return func(string) (bool, error) {
					calls++
					if stage == "match" {
						return false, errors.New("match failure")
					}
					return true, nil
				}, nil
			})
			if stage == "success" {
				require.True(t, predicate("keep.ts"), "injected matcher must be selected")
				require.Equal(t, 1, calls)
				require.NotContains(t, logs.String(), "falling back")
				return
			}
			require.True(t, predicate("drop.log"))
			require.False(t, predicate("keep.ts"))
			require.Equal(t, 1, strings.Count(logs.String(), "falling back"))
		})
	}
}

func TestFileFilter_RipgrepWorktreeMetadata(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{".git", "nested/.git", "keep.ts", "nested/keep.ts"} {
		createFileInPath(t, filepath.Join(root, p), []byte("gitdir: /another/worktree"))
	}
	for _, enabled := range []bool{false, true} {
		filter := NewFileFilter(root, &log.Logger, WithConfig(newTestConfig(map[string]bool{fileFilterRipgrepEnabled: enabled})))
		rules, err := filter.GetRules(nil)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"keep.ts", "nested/keep.ts"}, ripgrepFilteredPaths(t, filter, root, rules), "ripgrep=%t", enabled)
	}
}

func TestFileFilter_RipgrepRelativeRoots(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	for _, p := range []string{"project/drop.log", "project/keep.ts", "project/nested/drop.ts", "project/nested/keep.ts"} {
		createFileInPath(t, filepath.Join(root, p), nil)
	}
	createFileInPath(t, filepath.Join(root, "project/.gitignore"), []byte("*.log\n"))
	createFileInPath(t, filepath.Join(root, "project/nested/.gitignore"), []byte("*.ts\n!keep.ts\n"))
	for _, scanRoot := range []string{".", "project"} {
		for _, enabled := range []bool{false, true} {
			filter := NewFileFilter(scanRoot, &log.Logger, WithConfig(newTestConfig(map[string]bool{
				fileFilterRipgrepEnabled: enabled, FF_FILE_FILTER_METACHARACTER_FIX: true,
			})))
			rules, err := filter.GetRules([]string{".gitignore"})
			require.NoError(t, err)
			want := []string{".gitignore", "keep.ts", "nested/.gitignore", "nested/keep.ts"}
			if scanRoot == "." {
				for i := range want {
					want[i] = "project/" + want[i]
				}
			}
			require.ElementsMatch(t, want, ripgrepFilteredPaths(t, filter, scanRoot, rules), "root=%s/ripgrep=%t", scanRoot, enabled)
		}
	}
}

func ripgrepFilteredPaths(t *testing.T, filter *FileFilter, root string, rules []string) []string {
	t.Helper()
	var paths []string
	for file := range filter.GetFilteredFiles(filter.GetAllFiles(), rules) {
		relative, err := filepath.Rel(root, file)
		require.NoError(t, err)
		paths = append(paths, filepath.ToSlash(relative))
	}
	slices.Sort(paths)
	return paths
}
