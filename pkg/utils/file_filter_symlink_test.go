package utils

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

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

func TestGetAllFiles_SkipsSymlinks(t *testing.T) {
	root := createSymlinkTree(t)

	files := drainFilteredFiles(t, NewFileFilter(root, &log.Logger).GetAllFiles())

	assert.ElementsMatch(t, []string{filepath.Join(root, "real.js"), filepath.Join(root, "real-dir", "file.js")}, files)
}

func TestGetRules_IgnoresSymlinkedRuleFile(t *testing.T) {
	root := t.TempDir()
	rules := filepath.Join(t.TempDir(), "rules")
	createFileInPath(t, rules, []byte("*.js\n"))
	symlinkOrSkip(t, rules, filepath.Join(root, ".gitignore"))
	createFileInPath(t, filepath.Join(root, "a.js"), []byte("x"))
	fileFilter := NewFileFilter(root, &log.Logger)

	globs, err := fileFilter.GetRules([]string{".gitignore"})
	require.NoError(t, err)

	assert.Equal(t, []string{"**/.git/**"}, globs)
	assert.Equal(t, []string{filepath.Join(root, "a.js")}, drainFilteredFiles(t, fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs)))
}

func TestGetFilteredFiles_ExcludesSymlinks(t *testing.T) {
	root := createSymlinkTree(t)
	fileFilter := NewFileFilter(root, &log.Logger)
	globs := []string{"**/.git/**"}

	cases := []struct {
		input string
		kept  bool
	}{
		{input: filepath.Join(root, "real.js"), kept: true},
		{input: filepath.Join(root, "real-dir", "file.js"), kept: true},
		{input: filepath.Join(root, "linked_vuln.js")},
		{input: filepath.Join(root, "inside-link.js")},
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
}

func TestGetAllFiles_ListsSymlinksWithoutGitSemantics(t *testing.T) {
	root := createSymlinkTree(t)

	config := newTestConfig(map[string]bool{FF_FILE_FILTER_GIT_SEMANTICS: false})
	files := drainFilteredFiles(t, NewFileFilter(root, &log.Logger, WithConfig(config)).GetAllFiles())

	expected := []string{
		filepath.Join(root, "real.js"),
		filepath.Join(root, "real-dir", "file.js"),
		filepath.Join(root, "linked_vuln.js"),
		filepath.Join(root, "inside-link.js"),
		filepath.Join(root, "linked-dir"),
	}
	assert.ElementsMatch(t, expected, files)
}

func TestGetRules_ReadsSymlinkedRuleFileWithoutGitSemantics(t *testing.T) {
	root := t.TempDir()
	rules := filepath.Join(t.TempDir(), "rules")
	createFileInPath(t, rules, []byte("*.js\n"))
	symlinkOrSkip(t, rules, filepath.Join(root, ".gitignore"))
	createFileInPath(t, filepath.Join(root, "a.js"), []byte("x"))

	config := newTestConfig(map[string]bool{FF_FILE_FILTER_GIT_SEMANTICS: false})
	fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config))

	globs, err := fileFilter.GetRules([]string{".gitignore"})
	require.NoError(t, err)

	expected := []string{"**/.git/**", filepath.ToSlash(filepath.Join(root, "**", "*.js")), filepath.ToSlash(filepath.Join(root, "**", "*.js", "**"))}
	assert.ElementsMatch(t, expected, globs)
	expectedFiles := []string{filepath.Join(root, ".gitignore")}
	assert.ElementsMatch(t, expectedFiles, drainFilteredFiles(t, fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs)))
}

func TestGetFilteredFiles_KeepsSymlinksWithoutGitSemantics(t *testing.T) {
	root := createSymlinkTree(t)
	config := newTestConfig(map[string]bool{FF_FILE_FILTER_GIT_SEMANTICS: false})
	fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config))
	inputs := []string{
		filepath.Join(root, "real.js"),
		filepath.Join(root, "real-dir", "file.js"),
		filepath.Join(root, "linked_vuln.js"),
		filepath.Join(root, "inside-link.js"),
		filepath.Join(root, "linked-dir"),
		filepath.Join(root, "linked-dir", "file.js"),
	}

	assert.ElementsMatch(t, inputs, drainFilteredFiles(t, fileFilter.GetFilteredFiles(filesChannel(inputs), []string{"**/.git/**"})))
}
