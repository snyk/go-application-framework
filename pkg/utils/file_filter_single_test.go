package utils

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var singleFileRuleFiles = []string{".gitignore", ".snyk"}

func singleFileTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		createFileInPath(t, filepath.Join(root, filepath.FromSlash(name)), []byte(content))
	}
	return root
}

func singleFileFilter(file string, options ...FileFilterOption) *FileFilter {
	sections := WithDotSnykSections([]DotSnykExcludeSectionName{DotSnykExcludeGlobal, DotSnykExcludeSecrets})
	return NewFileFilter(file, &log.Logger, append(options, sections)...)
}

func requireAllowed(t *testing.T, want bool, file string, options ...FileFilterOption) {
	t.Helper()
	allowed, err := singleFileFilter(file, options...).IsFileAllowed(singleFileRuleFiles, nil)
	require.NoError(t, err)
	assert.Equal(t, want, allowed, file)
}

func TestIsFileAllowed(t *testing.T) {
	const excludeSecret, excludeAnywhere = "exclude:\n  global:\n    - secret.txt\n", "exclude:\n  global:\n    - '**/secret.txt'\n"
	tests := []struct {
		name  string
		files map[string]string
		input string
		want  bool
	}{
		{"gitignored file at root", map[string]string{".gitignore": ".env\n", ".env": "x"}, ".env", false},
		{"non-ignored file at root", map[string]string{".gitignore": ".env\n", "main.go": "x"}, "main.go", true},
		{"gitignored file in subdirectory", map[string]string{".gitignore": ".env\n", "sub/.env": "x"}, "sub/.env", false},
		{"non-ignored file in subdirectory", map[string]string{".gitignore": ".env\n", "sub/config.go": "x"}, "sub/config.go", true},
		{"wildcard pattern", map[string]string{".gitignore": "*.key\n", "server.key": "x"}, "server.key", false},
		{"root rule applies through an empty nested gitignore", map[string]string{".gitignore": ".env\n", "sub/.gitignore": "", "sub/.env": "x"}, "sub/.env", false},
		{"nested negation overrides the parent rule", map[string]string{".gitignore": "*.env\n", "sub/.gitignore": "!keep.env\n", "sub/keep.env": "x"}, "sub/keep.env", true},
		{"rule of a sibling directory does not apply", map[string]string{"other/.gitignore": "main.go\n", "sub/main.go": "x"}, "sub/main.go", true},
		{"rule anchored in a nested directory does not escape it", map[string]string{"sub/.gitignore": "/main.go\n", "sub/deeper/main.go": "x"}, "sub/deeper/main.go", true},
		{"ignore files above the repository root do not apply", map[string]string{".gitignore": "main.go\n", "repo/.git/HEAD": "x", "repo/.gitignore": "*.log\n", "repo/sub/main.go": "x"}, "repo/sub/main.go", true},
		{"rule file that is a directory is skipped", map[string]string{".snyk/x": "x", "a.txt": "x"}, "a.txt", true},
		{"files under .git", map[string]string{".git/config": "x"}, ".git/config", false},
		{"without a git repository every ancestor applies", map[string]string{".gitignore": "*.log\n", "a/b/.gitignore": "", "a/b/c/debug.log": "x"}, "a/b/c/debug.log", false},
		{"root dotsnyk applies through a nested gitignore", map[string]string{".snyk": excludeAnywhere, "a/b/.gitignore": "*.log\n", "a/b/secret.txt": "x"}, "a/b/secret.txt", false},
		{"nested dotsnyk is relative to its directory", map[string]string{"sub/.snyk": excludeSecret, "sub/secret.txt": "x"}, "sub/secret.txt", false},
		{"nested dotsnyk does not apply outside its directory", map[string]string{"sub/.snyk": excludeSecret, "secret.txt": "x"}, "secret.txt", true},
		{"root dotsnyk applies without other ignore files", map[string]string{".snyk": excludeAnywhere, "a/b/c/secret.txt": "x"}, "a/b/c/secret.txt", false},
		{"dotsnyk global exclude", map[string]string{".snyk": excludeSecret, "secret.txt": "x"}, "secret.txt", false},
		{"file in no ignore list", map[string]string{".gitignore": ".env\n", ".snyk": excludeSecret, "ok.txt": "x"}, "ok.txt", true},
		{"dotsnyk secrets section", map[string]string{".snyk": "exclude:\n  secrets:\n    - 'fixtures/**'\n", "fixtures/key.txt": "x"}, "fixtures/key.txt", false},
		{"dotsnyk code section is not requested", map[string]string{".snyk": "exclude:\n  code:\n    - 'c.txt'\n", "c.txt": "x"}, "c.txt", true},
		{"expired dotsnyk exclude", map[string]string{".snyk": "exclude:\n  global:\n    - old.txt:\n        expires: 2000-01-01\n", "old.txt": "x"}, "old.txt", true},
		{"unexpired dotsnyk exclude", map[string]string{".snyk": "exclude:\n  global:\n    - new.txt:\n        expires: 2999-01-01\n", "new.txt": "x"}, "new.txt", false},
	}
	for name, option := range gitSemanticsStates() {
		t.Run(name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					requireAllowed(t, tt.want, filepath.Join(singleFileTree(t, tt.files), filepath.FromSlash(tt.input)), option)
				})
			}
		})
	}
}

func TestIsFileAllowed_GlobsRelativeAndErrors(t *testing.T) {
	root := singleFileTree(t, map[string]string{"a.txt": "x", "b.go": "x", "b": "x", "c.txt": "x", "x.txt": "x", ".gitignore": "b\n!a.txt\nx.txt\n", ".snyk": "exclude:\n  global:\n    - '!x.txt'\n"})
	for _, names := range [][]string{singleFileRuleFiles, {".snyk", ".gitignore"}} {
		for file, want := range map[string]bool{"a.txt": true, "c.txt": false, "b.go": true, "x.txt": true} {
			allowed, err := singleFileFilter(filepath.Join(root, file)).IsFileAllowed(names, []string{"**/*.txt"})
			require.NoError(t, err)
			assert.Equal(t, want, allowed, file)
		}
	}
	t.Chdir(root)
	requireAllowed(t, true, "a.txt")
	requireAllowed(t, false, "b")
	_, err := singleFileFilter(root).IsFileAllowed(singleFileRuleFiles, nil)
	require.ErrorContains(t, err, "is a directory")
	_, err = singleFileFilter(filepath.Join(root, "missing.go")).IsFileAllowed(singleFileRuleFiles, nil)
	require.ErrorIs(t, err, fs.ErrNotExist)
	skipWithoutPermissions(t)
	lockPath(t, filepath.Join(root, ".gitignore"), 0o644)
	_, err = singleFileFilter(filepath.Join(root, "a.txt")).IsFileAllowed(singleFileRuleFiles, nil)
	require.ErrorIs(t, err, fs.ErrPermission)
}

func TestIsFileAllowed_NegationInExcludedFolder(t *testing.T) {
	for _, marker := range []string{"not-git", ".git/HEAD"} {
		for _, gitSemantics := range []bool{true, false} {
			root := singleFileTree(t, map[string]string{marker: "x", ".gitignore": "sub/\n!sub/keep.go\n", "sub/keep.go": "x"})
			requireAllowed(t, marker == "not-git" || !gitSemantics, filepath.Join(root, "sub", "keep.go"), WithConfig(newTestConfig(map[string]bool{FF_FILE_FILTER_GIT_SEMANTICS: gitSemantics})))
		}
	}
}

func TestIsFileAllowed_ThroughDirectorySymlink(t *testing.T) {
	for name, option := range gitSemanticsStates() {
		t.Run(name, func(t *testing.T) {
			for _, marker := range []string{"not-git", ".git/HEAD"} {
				root := singleFileTree(t, map[string]string{marker: "x", "real/.gitignore": "*.log\n", "real/main.go": "x", "real/debug.log": "x", "real/sub/y.go": "x", "x.go": "x"})
				alias := filepath.Join(root, "alias")
				symlinkOrSkip(t, "real", alias)
				symlinkOrSkip(t, filepath.Join("real", "sub"), filepath.Join(root, "ln"))
				requireAllowed(t, true, root+"/ln/../x.go", option)
				if marker != ".git/HEAD" {
					requireAllowed(t, true, filepath.Join(alias, "main.go"), option)
					requireAllowed(t, false, filepath.Join(alias, "debug.log"), option)
					continue
				}
				// The rule file behind a symlinked folder below the boundary must not even be opened.
				lockPath(t, filepath.Join(root, "real", ".gitignore"), 0o644)
				skipped := &skippedRecorder{}
				requireAllowed(t, false, filepath.Join(alias, "main.go"), option, WithSkippedPathHandler(skipped.handle))
				skipped.requireReportedOnce(t, alias)
			}
		})
	}
}

func TestIsFileAllowed_SymlinkedFile(t *testing.T) {
	for name, option := range gitSemanticsStates() {
		t.Run(name, func(t *testing.T) {
			root := singleFileTree(t, map[string]string{"real.go": "x"})
			link, broken := filepath.Join(root, "link.go"), filepath.Join(root, "broken.go")
			symlinkOrSkip(t, "real.go", link)
			symlinkOrSkip(t, "missing.go", broken)
			skipped := &skippedRecorder{}
			for _, file := range []string{link, broken} {
				filter := singleFileFilter(file, option, WithSkippedPathHandler(skipped.handle))
				for range 2 {
					allowed, err := filter.IsFileAllowed(singleFileRuleFiles, nil)
					var symlinkErr *SymlinkError
					require.ErrorAs(t, err, &symlinkErr)
					assert.Equal(t, file, symlinkErr.Path)
					assert.False(t, allowed)
				}
			}
			skipped.requireReportedOnce(t, link, broken)
		})
	}
}

func TestIsFileAllowed_TrackedFile(t *testing.T) {
	root := singleFileTree(t, map[string]string{".gitignore": "*.env\n", "tracked.env": "x"})
	repo, err := git.PlainInit(root, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add("tracked.env")
	require.NoError(t, err)
	for _, enabled := range []bool{false, true} {
		requireAllowed(t, enabled, filepath.Join(root, "tracked.env"), WithConfig(newTestConfig(map[string]bool{FF_GITIGNORE_RESPECT_TRACKED_FILES: enabled})))
	}
}

func TestIsFileAllowed_SkipsSymlinkedRuleFile(t *testing.T) {
	for name, option := range gitSemanticsStates() {
		t.Run(name, func(t *testing.T) {
			root := singleFileTree(t, map[string]string{"a.js": "x"})
			rules := filepath.Join(singleFileTree(t, map[string]string{"rules": "*.js\n"}), "rules")
			ruleLink := filepath.Join(root, ".gitignore")
			symlinkOrSkip(t, rules, ruleLink)
			skipped, recorder := &skippedRecorder{}, newMetricsRecorder(t)
			requireAllowed(t, true, filepath.Join(root, "a.js"), option, WithSkippedPathHandler(skipped.handle), WithMetrics(recorder))
			skipped.requireReportedOnce(t, ruleLink)
			assert.Equal(t, 1, recordedMetrics(t, recorder)[metricVariantLegacy].ints["symlinks.skippedCount"])
		})
	}
}
