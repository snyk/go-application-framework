package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if errors.Is(err, errWindowsPrivilegeNotHeld) {
			t.Skip("creating symlinks on Windows needs Developer Mode or administrator rights")
		}
		require.NoError(t, err)
	}
}

// createSymlinkTree creates real.js and real-dir/file.js below root, plus a link to a file outside
// root, a link to real.js and a link to real-dir.
func createSymlinkTree(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	outside := t.TempDir()
	createFileInPath(t, filepath.Join(root, "real.js"), []byte("x"))
	createFileInPath(t, filepath.Join(root, "real-dir", "file.js"), []byte("x"))
	createFileInPath(t, filepath.Join(outside, "vuln.js"), []byte("x"))
	symlinkOrSkip(t, filepath.Join(outside, "vuln.js"), filepath.Join(root, "linked_vuln.js"))
	symlinkOrSkip(t, "real.js", filepath.Join(root, "inside-link.js"))
	symlinkOrSkip(t, "real-dir", filepath.Join(root, "linked-dir"))

	return root
}

func gitSemanticsStates() map[string]FileFilterOption {
	return map[string]FileFilterOption{
		"git semantics on":  WithConfig(newTestConfig(map[string]bool{FF_FILE_FILTER_GIT_SEMANTICS: true})),
		"git semantics off": WithConfig(newTestConfig(map[string]bool{FF_FILE_FILTER_GIT_SEMANTICS: false})),
	}
}

func TestGetAllFiles_SkipsSymlinks(t *testing.T) {
	for name, option := range gitSemanticsStates() {
		t.Run(name, func(t *testing.T) {
			root := createSymlinkTree(t)

			files := drainFilteredFiles(t, NewFileFilter(root, &log.Logger, option).GetAllFiles())

			assert.ElementsMatch(t, []string{filepath.Join(root, "real.js"), filepath.Join(root, "real-dir", "file.js")}, files)
		})
	}
}

func TestGetRules_IgnoresSymlinkedRuleFile(t *testing.T) {
	for name, option := range gitSemanticsStates() {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			rules := filepath.Join(t.TempDir(), "rules")
			createFileInPath(t, rules, []byte("*.js\n"))
			symlinkOrSkip(t, rules, filepath.Join(root, ".gitignore"))
			createFileInPath(t, filepath.Join(root, "a.js"), []byte("x"))
			fileFilter := NewFileFilter(root, &log.Logger, option)

			globs, err := fileFilter.GetRules([]string{".gitignore"})
			require.NoError(t, err)

			assert.Equal(t, []string{"**/.git/**"}, globs)
			assert.Equal(t, []string{filepath.Join(root, "a.js")}, drainFilteredFiles(t, fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs)))
		})
	}
}

func TestGetFilteredFiles_ExcludesSymlinks(t *testing.T) {
	for name, option := range gitSemanticsStates() {
		t.Run(name, func(t *testing.T) {
			root := createSymlinkTree(t)
			fileFilter := NewFileFilter(root, &log.Logger, option)
			globs := []string{"**/.git/**"}

			cases := []struct {
				input string
				kept  bool
			}{
				{input: filepath.Join(root, "real.js"), kept: true},
				{input: filepath.Join(root, "real-dir", "file.js"), kept: true},
				{input: filepath.Join(root, "linked_vuln.js")},
				{input: filepath.Join(root, "inside-link.js")},
				{input: filepath.Join(root, "linked-dir")},
				{input: filepath.Join(root, "linked-dir", "file.js")},
				{input: filepath.Join(root, "missing.js"), kept: true},
			}

			var inputs, expected []string
			for _, tc := range cases {
				inputs = append(inputs, tc.input)
				if tc.kept {
					expected = append(expected, tc.input)
				}
				t.Run(filepath.Base(tc.input), func(t *testing.T) {
					got := drainFilteredFiles(t, fileFilter.GetFilteredFiles(filesChannel([]string{tc.input}), globs))
					assert.Equal(t, tc.kept, len(got) == 1, "%s returned %q", tc.input, got)
				})
			}

			assert.ElementsMatch(t, expected, drainFilteredFiles(t, fileFilter.GetFilteredFiles(filesChannel(inputs), globs)))
		})
	}
}

func symlinkedRoots(t *testing.T) []struct{ name, root string } {
	t.Helper()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	createFileInPath(t, filepath.Join(target, "secret.js"), []byte("x"))
	createFileInPath(t, filepath.Join(target, ".gitignore"), []byte("*.js\n"))
	link := filepath.Join(dir, "link")
	symlinkOrSkip(t, target, link)

	return []struct{ name, root string }{
		{name: "symlinked root", root: link},
		{name: "symlinked root with trailing separator", root: link + string(os.PathSeparator)},
	}
}

func TestGetRules_SymlinkedRoot(t *testing.T) {
	for name, option := range gitSemanticsStates() {
		t.Run(name, func(t *testing.T) {
			for _, tc := range symlinkedRoots(t) {
				t.Run(tc.name, func(t *testing.T) {
					globs, err := NewFileFilter(tc.root, &log.Logger, option).GetRules([]string{".gitignore"})

					var symlinkErr *SymlinkError
					require.ErrorAs(t, err, &symlinkErr)
					assert.Equal(t, tc.root, symlinkErr.Path)
					assert.Nil(t, globs)
				})
			}
		})
	}
}

func TestGetAllFiles_SymlinkedRoot(t *testing.T) {
	for name, option := range gitSemanticsStates() {
		t.Run(name, func(t *testing.T) {
			for _, tc := range symlinkedRoots(t) {
				t.Run(tc.name, func(t *testing.T) {
					var logs bytes.Buffer
					logger := zerolog.New(&logs)
					fileFilter := NewFileFilter(tc.root, &logger, option)

					assert.Empty(t, drainFilteredFiles(t, fileFilter.GetAllFiles()))
					assert.Empty(t, drainFilteredFiles(t, fileFilter.GetAllFiles()))

					lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
					require.Len(t, lines, 1, logs.String())
					var entry map[string]any
					require.NoError(t, json.Unmarshal([]byte(lines[0]), &entry))
					assert.Equal(t, "warn", entry["level"])
					assert.Equal(t, tc.root+" is a symbolic link. Snyk does not follow symbolic links; pass the real path instead.", entry["error"])
				})
			}
		})
	}
}

func TestGetAllFiles_RealRootWithTrailingSeparator(t *testing.T) {
	for name, option := range gitSemanticsStates() {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			createFileInPath(t, filepath.Join(root, "a.js"), []byte("x"))
			createFileInPath(t, filepath.Join(root, "dir", "b.js"), []byte("x"))

			files := drainFilteredFiles(t, NewFileFilter(root+string(os.PathSeparator), &log.Logger, option).GetAllFiles())

			assert.ElementsMatch(t, []string{filepath.Join(root, "a.js"), filepath.Join(root, "dir", "b.js")}, files)
		})
	}
}
