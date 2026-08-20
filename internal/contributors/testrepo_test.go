package contributors

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testBranch  = "main"
	testLogFile = "log.txt"
)

// testBaseCommitDate is far enough in the past that the base commit never counts
// as a contribution of its own.
var testBaseCommitDate = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// commit describes one commit to create in a test repository.
type commit struct {
	name  string
	email string
	when  time.Time

	// branch defaults to main if zero. It is used to build a repo with
	// commits on multiple branches, that are not reachable from eachother.
	branch string

	// remote makes branch exist only as a remote-tracking ref, as if it
	// were never checked out locally.
	remote bool

	// committerWhen defaults to when if zero. It is used to explicitly build a
	// commit whose committer date is different from its author date, e.g. to
	// simulate a rebase or amend.
	committerWhen time.Time
}

// testRepo is a git repository in a temporary directory, built by running the
// git CLI. The CLI is used rather than go-git because the checkout shapes that
// consumers scan in the wild - shallow clones and linked worktrees - cannot be
// created with go-git.
type testRepo struct {
	t    *testing.T
	dir  string
	home string
}

// newTestRepo creates a repository containing the given commits, in order, and
// leaves main checked out.
func newTestRepo(t *testing.T, commits ...commit) *testRepo {
	t.Helper()

	r := &testRepo{t: t, dir: t.TempDir(), home: t.TempDir()}
	r.git("init", "--initial-branch="+testBranch, ".")

	// A base commit gives every branch a common ancestor, so a test only has to
	// describe the commits it cares about.
	r.gitAs(identity("base", "base", testBaseCommitDate, testBaseCommitDate), "commit", "--allow-empty", "-m", "base commit")
	base := r.git("rev-parse", "HEAD")

	branches := groupByBranch(commits)
	for _, b := range branches {
		if b.name != testBranch {
			r.git("checkout", "-b", b.name, base)
		}
		for i, c := range b.commits {
			r.addCommit(i, c)
		}
	}
	r.git("checkout", testBranch)

	for _, b := range branches {
		if b.remoteOnly {
			r.git("update-ref", "refs/remotes/origin/"+b.name, r.git("rev-parse", b.name))
			r.git("branch", "-D", b.name)
		}
	}

	return r
}

// newEmptyTestRepo creates a repository with no commits. Pass --bare for one
// without a worktree.
func newEmptyTestRepo(t *testing.T, initArgs ...string) *testRepo {
	t.Helper()

	r := &testRepo{t: t, dir: t.TempDir(), home: t.TempDir()}
	r.git(append(append([]string{"init"}, initArgs...), "--initial-branch="+testBranch, ".")...)
	return r
}

// path returns the directory to scan.
func (r *testRepo) path() string {
	return r.dir
}

// detach checks the current commit out directly, leaving HEAD detached.
func (r *testRepo) detach() *testRepo {
	r.t.Helper()

	r.git("checkout", "--detach", "HEAD")
	return r
}

// deleteBranch removes a local branch, leaving its commits reachable only from
// whatever else still points at them.
func (r *testRepo) deleteBranch(name string) *testRepo {
	r.t.Helper()

	r.git("branch", "-D", name)
	return r
}

// shallowClone returns a clone truncated to the last depth commits, as a CI job
// cloning with --depth gets. The clone goes over file:// because git ignores
// --depth when cloning a plain local path.
func (r *testRepo) shallowClone(depth int) *testRepo {
	r.t.Helper()

	clone := &testRepo{t: r.t, dir: filepath.Join(r.t.TempDir(), "clone"), home: r.home}
	r.git("clone", "--depth", strconv.Itoa(depth), "file://"+r.dir, clone.dir)
	return clone
}

// worktree returns a linked worktree on a new branch, which keeps its objects
// and refs in this repository rather than its own git directory.
func (r *testRepo) worktree() *testRepo {
	r.t.Helper()

	return r.addWorktree()
}

// detachedWorktree returns a linked worktree with a detached HEAD.
func (r *testRepo) detachedWorktree() *testRepo {
	r.t.Helper()

	return r.addWorktree("--detach")
}

// remove deletes the repository from disk, e.g. to orphan a worktree of it.
func (r *testRepo) remove() {
	r.t.Helper()

	require.NoError(r.t, os.RemoveAll(r.dir))
}

func (r *testRepo) addWorktree(args ...string) *testRepo {
	r.t.Helper()

	worktree := &testRepo{t: r.t, dir: filepath.Join(r.t.TempDir(), "worktree"), home: r.home}
	r.git(append(append([]string{"worktree", "add"}, args...), worktree.dir)...)
	return worktree
}

func (r *testRepo) addCommit(seq int, c commit) {
	r.t.Helper()

	content := fmt.Appendf(nil, "%d %s", seq, c.email)
	require.NoError(r.t, os.WriteFile(filepath.Join(r.dir, testLogFile), content, 0o600))

	name := c.name
	if name == "" {
		name = "Test Author"
	}

	committerWhen := c.committerWhen
	if committerWhen.IsZero() {
		committerWhen = c.when
	}

	r.git("add", testLogFile)
	r.gitAs(identity(name, c.email, c.when, committerWhen), "commit", "-m", fmt.Sprintf("commit %d", seq))
}

// git runs a git command in the repository and returns its trimmed output.
func (r *testRepo) git(args ...string) string {
	r.t.Helper()

	return r.gitAs(nil, args...)
}

// gitAs runs a git command with extra environment appended.
func (r *testRepo) gitAs(extra []string, args ...string) string {
	r.t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(isolatedGitEnv(r.home), extra...)

	out, err := cmd.CombinedOutput()
	require.NoErrorf(r.t, err, "git %s: %s", strings.Join(args, " "), out)
	return strings.TrimSpace(string(out))
}

// branchCommits is the commits of one branch, in the order they were given.
type branchCommits struct {
	name       string
	commits    []commit
	remoteOnly bool
}

// groupByBranch splits commits by branch, keeping the order the branches were
// first mentioned in so that repositories build the same way every run.
func groupByBranch(commits []commit) []branchCommits {
	var branches []branchCommits
	index := map[string]int{}

	for _, c := range commits {
		name := c.branch
		if name == "" {
			name = testBranch
		}

		i, ok := index[name]
		if !ok {
			i = len(branches)
			index[name] = i
			branches = append(branches, branchCommits{name: name})
		}

		branches[i].commits = append(branches[i].commits, c)
		branches[i].remoteOnly = branches[i].remoteOnly || c.remote
	}

	return branches
}

// identity fixes who authored a commit and when.
func identity(name, email string, authored, committed time.Time) []string {
	return []string{
		"GIT_AUTHOR_NAME=" + name,
		"GIT_AUTHOR_EMAIL=" + email,
		"GIT_AUTHOR_DATE=" + authored.Format(time.RFC3339),
		"GIT_COMMITTER_NAME=" + name,
		"GIT_COMMITTER_EMAIL=" + email,
		"GIT_COMMITTER_DATE=" + committed.Format(time.RFC3339),
	}
}

// isolatedGitEnv ignores the developer's own git configuration, so that a global
// setting like commit.gpgsign cannot change what a test builds.
func isolatedGitEnv(home string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			env = append(env, kv)
		}
	}

	return append(env,
		"HOME="+home,
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_SYSTEM="+os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	)
}
