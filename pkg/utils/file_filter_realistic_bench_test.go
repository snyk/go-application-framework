package utils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/require"
)

// Four realistic workloads, each on a repository with a real .git folder. The fixture cannot start
// background git maintenance and waits until git is idle before measuring: a `git commit` that
// left `git maintenance run --auto` running repacked the repository and deleted .git/objects/XX
// folders while the implementation under test walked .git. CPU time comes from processCPUTime in
// the unix and windows files.
//
//	go test ./pkg/utils -run '^$' -bench '^BenchmarkRealisticTree225k31kRules$' -benchmem -benchtime=3x -v

func BenchmarkRealisticTracked200kFlat(b *testing.B) {
	runBenchmark(b, "tracked-200k-flat", populateTracked200kFlat)
}

func BenchmarkRealisticTree225k36kRules(b *testing.B) {
	runBenchmark(b, "tree-225k-3.6k-rules", populateTree225k36kRules)
}

func BenchmarkRealisticTree225k31kRules(b *testing.B) {
	runBenchmark(b, "tree-225k-31k-rules", populateTree225k31kRules)
}

func BenchmarkRealisticMonorepoNodeModules(b *testing.B) {
	runBenchmark(b, "monorepo-node-modules", populateMonorepoNodeModules)
}

// gitQuiet are the options that stop git from starting background work. They are passed with -c on
// every call that can trigger maintenance and are also written to the repository's local config.
var gitQuiet = []string{"-c", "maintenance.auto=false", "-c", "gc.auto=0", "-c", "gc.autoDetach=false"}

type fixture struct {
	root string
	// forced lists ignored files that are tracked anyway, added with git update-index.
	forced      []string
	rules       int
	ignoreFiles int
}

func runBenchmark(b *testing.B, name string, populate func(testing.TB, *fixture)) {
	b.Helper()

	isolateGit(b)

	root, err := os.MkdirTemp("", "cli2075-realistic-"+name+"-")
	require.NoError(b, err)
	b.Cleanup(func() { _ = os.RemoveAll(root) })

	b.Logf("runtime.NumCPU()=%d runtime.GOMAXPROCS(0)=%d GOOS=%s GOARCH=%s", runtime.NumCPU(), runtime.GOMAXPROCS(0), runtime.GOOS, runtime.GOARCH)

	fx := &fixture{root: root}
	populate(b, fx)
	fx.commit(b)
	waitForGitIdle(b, root)

	indexRead, entries := timeIndexRead(b, root)
	wantFiles := oracleCount(b, root)
	b.Logf("%s: %d .gitignore files, %d rules; index read %s for %d entries; git ls-files lists %d files",
		name, fx.ignoreFiles, fx.rules, indexRead, entries, wantFiles)

	for _, impl := range scenarioImplementations {
		b.Run(impl.name, func(b *testing.B) {
			b.ReportAllocs()

			var returned int
			cpuBefore := processCPUTime(b)
			b.ResetTimer()
			for range b.N {
				returned = len(impl.run(b, root, scenarioOptions{}))
			}
			b.StopTimer()
			cpu := processCPUTime(b) - cpuBefore

			b.ReportMetric(float64(cpu)/float64(time.Millisecond)/float64(b.N), "cpu-ms/op")
			b.ReportMetric(float64(returned), "files")
			if returned != wantFiles {
				b.Errorf("%s/%s returned %d files, git ls-files lists %d", impl.name, name, returned, wantFiles)
			}
		})
	}
}

// TestFixtureRaceProof runs the current implementation three times on the 31k-rule tree and
// compares every result with git ls-files. Without the maintenance guard, the current
// implementation returned 0 files on macOS.
func TestFixtureRaceProof(t *testing.T) {
	if os.Getenv("CLI2075_RACE_PROOF") == "" {
		t.Skip("set CLI2075_RACE_PROOF=1: builds a 243,000-file tree")
	}

	isolateGit(t)

	root, err := os.MkdirTemp("", "cli2075-realistic-raceproof-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	fx := &fixture{root: root}
	populateTree225k31kRules(t, fx)
	fx.commit(t)
	waitForGitIdle(t, root)

	wantFiles := oracleCount(t, root)
	objectsBefore := gitCmd(t, root, "count-objects", "-v")
	t.Logf("git ls-files lists %d files; count-objects before:\n%s", wantFiles, objectsBefore)

	var current scenarioImplementation
	for _, impl := range scenarioImplementations {
		if impl.name == currentImplementationName {
			current = impl
		}
	}
	require.NotEmpty(t, current.name, "current implementation not registered")

	for run := 1; run <= 3; run++ {
		start := time.Now()
		returned := len(current.run(t, root, scenarioOptions{}))
		t.Logf("run %d: current returned %d files, git ls-files lists %d, took %s", run, returned, wantFiles, time.Since(start))
		require.Equal(t, wantFiles, returned, "run %d", run)
	}

	objectsAfter := gitCmd(t, root, "count-objects", "-v")
	t.Logf("count-objects after:\n%s", objectsAfter)
	require.Equal(t, objectsBefore, objectsAfter, "the object store changed while the benchmark ran")
}

// isolateGit points HOME and the git config at empty places, so only the workload's own rules apply.
// go-git reads the global git config through the home folder, so the home variables change too.
func isolateGit(tb testing.TB) {
	tb.Helper()

	home, err := os.MkdirTemp("", "cli2075-realistic-home-")
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = os.RemoveAll(home) })

	tb.Setenv("HOME", home)
	tb.Setenv("USERPROFILE", home)
	tb.Setenv("XDG_CONFIG_HOME", home)
	// "/dev/null" on every OS: git for Windows maps it, but rejects "NUL" here.
	tb.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	tb.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}

func gitCmd(tb testing.TB, dir string, args ...string) string {
	tb.Helper()

	return gitWithStdin(tb, dir, "", args...)
}

func gitWithStdin(tb testing.TB, dir, stdin string, args ...string) string {
	tb.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(tb, cmd.Run(), "git %v\n%s", args, stderr.String())

	return stdout.String()
}

// write creates a file with empty content. The implementations never read file content, and empty
// files take no data blocks, so a 225k-file tree fits on a small disk.
func (fx *fixture) write(tb testing.TB, rel, content string) {
	tb.Helper()

	full := filepath.Join(fx.root, filepath.FromSlash(rel))
	require.NoError(tb, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(tb, os.WriteFile(full, []byte(content), 0o644))
}

func (fx *fixture) writeIgnoreFile(tb testing.TB, dirRel string, rules []string) {
	tb.Helper()

	fx.write(tb, path.Join(dirRel, ".gitignore"), ruleLines(rules...))
	fx.rules += len(rules)
	fx.ignoreFiles++
}

// commit builds the repository with maintenance switched off in the repository config and on every
// command that can start it. git add -A skips ignored files, so they stay untracked; forced files are
// added with update-index, which ignores the rules. The committer identity and signing are set on
// the command line because the isolated git config has neither.
func (fx *fixture) commit(tb testing.TB) {
	tb.Helper()

	gitCmd(tb, fx.root, "init", "-q")
	gitCmd(tb, fx.root, "config", "--local", "maintenance.auto", "false")
	gitCmd(tb, fx.root, "config", "--local", "gc.auto", "0")
	gitCmd(tb, fx.root, "config", "--local", "gc.autoDetach", "false")

	gitCmd(tb, fx.root, append(append([]string{}, gitQuiet...), "add", "-A")...)
	if len(fx.forced) > 0 {
		gitWithStdin(tb, fx.root, strings.Join(fx.forced, "\x00"), append(append([]string{}, gitQuiet...), "update-index", "--add", "-z", "--stdin")...)
	}
	gitCmd(tb, fx.root, append(append([]string{}, gitQuiet...),
		"-c", "user.name=bench", "-c", "user.email=bench@example.invalid", "-c", "commit.gpgsign=false",
		"commit", "-q", "-m", "fixture")...)
}

// waitForGitIdle blocks until no git maintenance process runs and the repository has no lock file or
// object-folder change for two polls in a row. With maintenance switched off nothing should be
// running; the wait makes a leak fail loudly instead of corrupting a measurement.
func waitForGitIdle(tb testing.TB, root string) {
	tb.Helper()

	const (
		poll    = 500 * time.Millisecond
		timeout = 5 * time.Minute
	)
	deadline := time.Now().Add(timeout)
	stablePolls := 0
	lastObjects := ""
	waited := false

	for time.Now().Before(deadline) {
		busy := gitMaintenanceProcesses(tb)
		for _, lock := range []string{"gc.pid", "maintenance.lock", "index.lock"} {
			if _, err := os.Stat(filepath.Join(root, ".git", lock)); err == nil {
				busy = append(busy, ".git/"+lock)
			}
		}
		locks, err := filepath.Glob(filepath.Join(root, ".git", "objects", "pack", "*.lock"))
		if err != nil {
			tb.Fatalf("listing pack locks: %v", err)
		}
		busy = append(busy, locks...)

		objects := gitCmd(tb, root, "count-objects", "-v")
		if len(busy) == 0 && objects == lastObjects {
			stablePolls++
		} else {
			stablePolls = 0
			waited = true
			if len(busy) > 0 {
				tb.Logf("waiting for git: %v", busy)
			}
		}
		lastObjects = objects

		if stablePolls >= 2 {
			if waited {
				tb.Logf("git is idle after waiting")
			}

			return
		}
		time.Sleep(poll)
	}

	tb.Fatalf("git was not idle after %s", timeout)
}

func oracleCount(tb testing.TB, root string) int {
	tb.Helper()

	output := gitCmd(tb, root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")

	return strings.Count(output, "\x00")
}

// timeIndexRead times the open and index read that the tracked-file path does once per scan.
func timeIndexRead(tb testing.TB, root string) (time.Duration, int) {
	tb.Helper()

	start := time.Now()
	repo, err := git.PlainOpenWithOptions(root, &git.PlainOpenOptions{DetectDotGit: true})
	require.NoError(tb, err)
	index, err := repo.Storer.Index()
	require.NoError(tb, err)

	return time.Since(start), len(index.Entries)
}

func unmatched(format string, n int) []string {
	rules := make([]string, n)
	for i := range n {
		rules[i] = fmt.Sprintf(format, i)
	}

	return rules
}

func folderRules(folder, count int) []string {
	rules := []string{"*.tmp"}
	for i := 1; i < count; i++ {
		rules = append(rules, fmt.Sprintf("gen-%04d-%02d.dat", folder, i))
	}

	return rules
}

// populateTracked200kFlat: 10,000 folders with 20 tracked files each and one untracked scratch file
// each, under one root .gitignore of 20 rules. The tracked.log files match a rule but are tracked,
// so they must be kept.
func populateTracked200kFlat(tb testing.TB, fx *fixture) {
	tb.Helper()

	rootRules := append([]string{"*.log", "*.tmp", "*.bak", "build/", "dist/", "/scratch-root.txt"}, unmatched("gen-%02d.dat", 14)...)
	fx.writeIgnoreFile(tb, "", rootRules)

	for group := range 100 {
		for folder := range 100 {
			dir := fmt.Sprintf("g%02d/d%03d", group, folder)
			for file := range 19 {
				fx.write(tb, fmt.Sprintf("%s/f%02d.txt", dir, file), "")
			}
			fx.write(tb, dir+"/tracked.log", "")
			fx.forced = append(fx.forced, dir+"/tracked.log")
			fx.write(tb, dir+"/scratch.tmp", "")
		}
	}
}

// populateNestedTree: 9,000 folders with 25 tracked files each. ignoreRules returns the rules for a
// folder's own .gitignore, or nil for no .gitignore. Folders with one get a tracked keep.tmp and an
// untracked scratch.tmp; folders without one leave scratch.tmp unignored.
func populateNestedTree(tb testing.TB, fx *fixture, ignoreRules func(folder int) []string) {
	tb.Helper()

	for folder := range 9000 {
		dir := fmt.Sprintf("g%02d/d%04d", folder/100, folder)
		for file := range 25 {
			fx.write(tb, fmt.Sprintf("%s/f%02d.txt", dir, file), "")
		}
		if rules := ignoreRules(folder); rules != nil {
			fx.writeIgnoreFile(tb, dir, rules)
			fx.write(tb, dir+"/keep.tmp", "")
			fx.forced = append(fx.forced, dir+"/keep.tmp")
		}
		fx.write(tb, dir+"/scratch.tmp", "")
	}
}

// populateTree225k36kRules: 360 of the 9,000 folders have a .gitignore, with 1 to 20 rules each.
func populateTree225k36kRules(tb testing.TB, fx *fixture) {
	tb.Helper()

	populateNestedTree(tb, fx, func(folder int) []string {
		if folder%25 != 0 {
			return nil
		}

		return folderRules(folder, 1+(folder/25)%20)
	})
}

// populateTree225k31kRules: every folder has a .gitignore with 1 to 6 rules (about 31.5k in total).
func populateTree225k31kRules(tb testing.TB, fx *fixture) {
	tb.Helper()

	populateNestedTree(tb, fx, func(folder int) []string {
		return folderRules(folder, 1+folder%6)
	})
}

// populateMonorepoNodeModules: 5,000 tracked source files, and 100,000 untracked files under an
// ignored node_modules folder. The root .gitignore has 500 rules.
func populateMonorepoNodeModules(tb testing.TB, fx *fixture) {
	tb.Helper()

	rules := []string{"node_modules/", "dist/", "*.log", "coverage/"}
	rules = append(rules, unmatched("gen-%03d/", 496)...)
	fx.writeIgnoreFile(tb, "", rules)

	for pkg := range 250 {
		for file := range 20 {
			fx.write(tb, fmt.Sprintf("src/pkg%03d/f%02d.ts", pkg, file), "")
		}
	}
	for pkg := range 1000 {
		for file := range 100 {
			fx.write(tb, fmt.Sprintf("node_modules/pkg%04d/m%02d.js", pkg, file), "")
		}
	}
}

// logCoreLimit records how many CPUs the process may use. Under taskset, runtime.NumCPU follows the
// affinity mask, and GOMAXPROCS follows NumCPU, so both show the limit that applied.
func logCoreLimit(tb testing.TB) {
	tb.Helper()

	tb.Logf("runtime.NumCPU()=%d runtime.GOMAXPROCS(0)=%d", runtime.NumCPU(), runtime.GOMAXPROCS(0))
}
