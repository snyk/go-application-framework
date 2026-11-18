package utils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRealRepositoryDiff compares every registered implementation with git ls-files on each
// repository listed in CLI2075_DIFF_REPOS (separated by the OS path-list separator). It logs the
// difference per implementation; it skips when the variable is unset.
//
// The oracle runs with the environment as it is, with no isolation, as a user's git would. A fresh
// clone has no untracked files, so the global excludes file cannot change its listing.
func TestRealRepositoryDiff(t *testing.T) {
	repos := os.Getenv("CLI2075_DIFF_REPOS")
	if repos == "" {
		t.Skip("CLI2075_DIFF_REPOS not set")
	}

	for _, repo := range filepath.SplitList(repos) {
		t.Run(filepath.Base(repo), func(t *testing.T) {
			oracle := gitListingAsIs(t, repo)
			t.Logf("oracle git ls-files lists %d files", len(oracle))

			for _, impl := range scenarioImplementations {
				t.Run(impl.name, func(t *testing.T) {
					got := normalizeScenarioResult(t, repo, impl.run(t, repo, scenarioOptions{}))
					missing, unexpected := diffPaths(oracle, got)
					slices.Sort(missing)
					slices.Sort(unexpected)

					t.Logf("DIFF %s %s: returned=%d only-in-oracle=%d only-in-impl=%d",
						filepath.Base(repo), impl.name, len(got), len(missing), len(unexpected))
					t.Logf("  only-in-oracle, first 10: %s", firstN(missing))
					t.Logf("  only-in-impl, first 10: %s", firstN(unexpected))
				})
			}
		})
	}
}

// gitListingAsIs is the oracle: git ls-files --cached --others --exclude-standard, with the
// environment as it is.
func gitListingAsIs(tb testing.TB, dir string) []string {
	tb.Helper()

	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(tb, cmd.Run(), "git ls-files in %s\n%s", dir, stderr.String())

	var listed []string
	for _, p := range strings.Split(stdout.String(), "\x00") {
		if p != "" {
			listed = append(listed, p)
		}
	}
	slices.Sort(listed)

	return listed
}

// maxListedPaths is how many paths a log line shows before it cuts the list.
const maxListedPaths = 10

func firstN(paths []string) string {
	if len(paths) == 0 {
		return "(none)"
	}
	if len(paths) > maxListedPaths {
		paths = paths[:maxListedPaths]
	}

	return fmt.Sprintf("%q", paths)
}
