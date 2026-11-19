//go:build unix

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boyter/gocodewalker"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// The probes below only log. They exist to show which behaviour comes from the library and which
// from the adapter, and never fail the run.

// rawGocodewalker runs the library with the adapter's options but none of its post-processing.
func rawGocodewalker(scanRoot string, configured bool) []string {
	queue := make(chan *gocodewalker.File, 1024)
	walker := gocodewalker.NewFileWalker(scanRoot, queue)
	if configured {
		walker.IncludeHidden = true
		walker.IgnoreIgnoreFile = true
		walker.IgnoreGitModules = true
		walker.ExcludeDirectory = []string{gocodewalkerGitDir}
	}
	go func() { _ = walker.Start() }()

	var files []string
	for f := range queue {
		files = append(files, f.Location)
	}

	return files
}

// TestGocodewalkerLibraryOnlyScenarios runs every scenario against the library alone, once with its
// defaults and once with the adapter's options, to attribute each adapter feature to a failure.
func TestGocodewalkerLibraryOnlyScenarios(t *testing.T) {
	for _, variant := range []struct {
		name       string
		configured bool
	}{{"library-defaults", false}, {"library-configured", true}} {
		t.Run(variant.name, func(t *testing.T) {
			for _, sc := range buildScenarios(t) {
				if sc.skipReason != "" {
					continue
				}
				scanRoot := buildScenarioRepo(t, sc)
				want := handWrittenWant(t, sc, scanRoot)
				got := dropLinkEntriesIfRequested(sc, normalizeScenarioResult(t, scanRoot, rawGocodewalker(scanRoot, variant.configured)))

				missing, unexpected := diffPaths(want, got)
				if len(missing) == 0 && len(unexpected) == 0 {
					t.Logf("MATCH %s", sc.name)
					continue
				}
				t.Logf("DIFF  %s\n  missing: %v\n  unexpected: %v", sc.name, missing, compactGitPaths(unexpected))
			}
		})
	}
}

// compactGitPaths folds the entries under .git/ into one marker so the log stays readable.
func compactGitPaths(paths []string) []string {
	var out []string
	gitEntries := 0
	for _, p := range paths {
		if strings.HasPrefix(p, ".git/") {
			gitEntries++
			continue
		}
		out = append(out, p)
	}
	if gitEntries > 0 {
		out = append(out, fmt.Sprintf("<%d entries under .git/>", gitEntries))
	}

	return out
}

type ruleProbeCase struct {
	name  string
	rules string
	files []string
}

// TestGocodewalkerRuleSyntaxAgainstGit compares the adapter with git on rule shapes beyond the
// scenario list. Nothing is tracked, so the result is what git ls-files --others lists.
func TestGocodewalkerRuleSyntaxAgainstGit(t *testing.T) {
	cases := []ruleProbeCase{
		{"anchored glob /*.txt", "/*.txt\n", []string{"a.txt", "d/b.txt", "d/e/c.txt"}},
		{"anchored path /d/*.txt", "/d/*.txt\n", []string{"d/a.txt", "d/e/b.txt", "x/d/c.txt"}},
		{"inner slash d/*.txt", "d/*.txt\n", []string{"d/a.txt", "d/e/b.txt", "x/d/c.txt"}},
		{"single-level wildcard dir */foo", "*/foo\n", []string{"a/foo", "a/b/foo", "foo"}},
		{"leading double star **/foo", "**/foo\n", []string{"foo", "a/foo", "a/b/foo", "a/bar"}},
		{"trailing double star d/**", "d/**\n", []string{"d/a", "d/e/b", "x/d/c"}},
		{"middle double star a/**/b", "a/**/b\n", []string{"a/b", "a/x/b", "a/x/y/b", "c/a/b"}},
		{"double star dir-only **/logs/", "**/logs/\n", []string{"logs/a", "x/logs/b", "z/logs"}},
		{"double star glob **/*.tmp", "**/*.tmp\n", []string{"a.tmp", "d/b.tmp", "d/e/c.tmp", "keep.txt"}},
		{"char class [ab].txt", "[ab].txt\n", []string{"a.txt", "b.txt", "c.txt", "d/a.txt"}},
		{"char class *.[ch]", "*.[ch]\n", []string{"x.c", "x.h", "x.o", "d/y.c"}},
		{"question mark ?.txt", "?.txt\n", []string{"a.txt", "ab.txt", "d/b.txt"}},
		{"escaped star \\*.txt", "\\*.txt\n", []string{"*.txt", "a.txt"}},
		{"contents re-include d/* and !d/keep", "d/*\n!d/keep\n", []string{"d/keep", "d/other", "d/sub/x"}},
		{"re-include under ignored dir", "d/\n!d/keep\n", []string{"d/keep", "d/other"}},
		{"floating dir build/ in subfolders", "build/\n", []string{"build/a", "x/build/b", "y/build"}},
		{"anchored dir /build/", "/build/\n", []string{"build/a", "x/build/b"}},
		{"floating name with dots", ".env\n", []string{".env", "d/.env", "d/.env.local"}},
		{"allowlist * !*/ !*.go", "*\n!*/\n!*.go\n", []string{"a.go", "d/b.go", "d/c.txt", "e.txt"}},
		{"negate then ignore again", "*.log\n!important.log\nimportant.log\n", []string{"important.log", "a.log"}},
		{"space in name", "my file.txt\n", []string{"my file.txt", "myfile.txt"}},
		{"unicode name", "caf\u00e9/\n", []string{"caf\u00e9/a", "cafe/a"}},
		{"leading space pattern", "\\ lead\n", []string{" lead", "lead"}},
		{"case sensitivity *.TXT", "*.TXT\n", []string{"a.txt", "b.TXT"}},
		{"deep inner slash a/b/c", "a/b/c\n", []string{"a/b/c", "x/a/b/c", "a/b/z"}},
		{"trailing slash only on glob */", "*/\n", []string{"a/x", "b", "c/d/e"}},
		{"double star only", "**\n!keep.txt\n", []string{"keep.txt", "a/keep.txt", "a/b"}},
		{"pattern with brackets in name", "a\\[1\\].txt\n", []string{"a[1].txt", "a1.txt"}},
		{"hash not comment when escaped", "\\#x\n#y\n", []string{"#x", "#y", "y"}},
	}

	isolateGit(t)

	var diffs int
	for _, tc := range cases {
		files := map[string]string{".gitignore": tc.rules}
		for _, f := range tc.files {
			files[f] = "x"
		}
		sc := scenario{name: tc.name, files: files, gitOracle: true, why: "rule shape"}
		scanRoot := buildScenarioRepo(t, sc)

		want := gitWant(t, sc, scanRoot)
		got := normalizeScenarioResult(t, scanRoot, gocodewalkerScan(scanRoot, nopLogger()))
		missing, unexpected := diffPaths(want, got)
		if len(missing) == 0 && len(unexpected) == 0 {
			t.Logf("MATCH %-40s rules=%q", tc.name, tc.rules)
			continue
		}
		diffs++
		t.Logf("DIFF  %-40s rules=%q\n    missing (git lists, adapter does not): %v\n    unexpected (adapter lists, git does not): %v", tc.name, tc.rules, missing, unexpected)
	}
	t.Logf("%d of %d rule shapes differ from git", diffs, len(cases))
}

func nopLogger() *zerolog.Logger {
	logger := zerolog.Nop()

	return &logger
}

// skipUnlessHeavyGocodewalkerProbes keeps the probes that build trees of tens of thousands of files
// out of a plain `go test`.
func skipUnlessHeavyGocodewalkerProbes(t *testing.T) {
	t.Helper()

	if os.Getenv("CLI2075_GOCODEWALKER_PROBES") == "" {
		t.Skip("set CLI2075_GOCODEWALKER_PROBES=1: builds trees of up to 100,000 files")
	}
}

// TestGocodewalkerConcurrencyShape records how many goroutines the walk starts and how long a
// single folder of 100k entries takes, using the library alone. It skips unless
// CLI2075_GOCODEWALKER_PROBES is set.
func TestGocodewalkerConcurrencyShape(t *testing.T) {
	skipUnlessHeavyGocodewalkerProbes(t)

	shapes := []struct {
		name    string
		folders int
		files   int
	}{
		{"1 folder, 100000 files", 1, 100000},
		{"1 top folder with 1000 subfolders of 100 files", -1, 100},
		{"2000 top folders, 50 files each", 2000, 50},
	}

	for _, shape := range shapes {
		root, err := os.MkdirTemp("", "cli2075-gocodewalker-shape-")
		require.NoError(t, err)
		defer os.RemoveAll(root)

		switch {
		case shape.folders == -1:
			for i := range 1000 {
				populateFolder(t, filepath.Join(root, "top", fmt.Sprintf("d%04d", i)), shape.files)
			}
		default:
			for i := range shape.folders {
				populateFolder(t, filepath.Join(root, fmt.Sprintf("d%04d", i)), shape.files)
			}
		}
		require.NoError(t, os.WriteFile(filepath.Join(root, ".gitignore"), []byte("*.log\nbuild/\n"), 0o644))

		var peak atomic.Int64
		stop := make(chan struct{})
		sampled := make(chan struct{})
		go func() {
			defer close(sampled)
			for {
				select {
				case <-stop:
					return
				default:
					if n := int64(runtime.NumGoroutine()); n > peak.Load() {
						peak.Store(n)
					}
					time.Sleep(200 * time.Microsecond)
				}
			}
		}()

		base := runtime.NumGoroutine()
		start := time.Now()
		files := rawGocodewalker(root, true)
		elapsed := time.Since(start)
		close(stop)
		<-sampled

		t.Logf("%-50s files=%d wall=%s peak goroutines above baseline=%d (NumCPU=%d)", shape.name, len(files), elapsed, peak.Load()-int64(base), runtime.NumCPU())
	}
}

func populateFolder(t *testing.T, dir string, files int) {
	t.Helper()

	require.NoError(t, os.MkdirAll(dir, 0o755))
	for i := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%06d.txt", i)), nil, 0o644))
	}
}

// TestGocodewalkerRetainedHeap measures what a walk leaves on the heap after it returns, using
// the library alone with a .gitignore at the root so the matcher runs for every path. It skips
// unless CLI2075_GOCODEWALKER_PROBES is set.
func TestGocodewalkerRetainedHeap(t *testing.T) {
	skipUnlessHeavyGocodewalkerProbes(t)

	root, err := os.MkdirTemp("", "cli2075-gocodewalker-heap-")
	require.NoError(t, err)
	defer os.RemoveAll(root)

	for i := range 2000 {
		populateFolder(t, filepath.Join(root, fmt.Sprintf("d%04d", i)), 25)
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, ".gitignore"), []byte("*.log\nbuild/\n"), 0o644))

	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)

		return stats.HeapAlloc
	}

	before := heap()
	files := rawGocodewalker(root, true)
	count := len(files)
	files = nil
	_ = files
	after := heap()
	t.Logf("walked %d files; heap retained after the result is dropped and the GC has run twice: %d KiB (%d bytes per walked file)",
		count, (int64(after)-int64(before))/1024, (int64(after)-int64(before))/int64(max(count, 1)))

	// A second walk of the same paths shows whether the retained amount grows per walk or per distinct path.
	files = rawGocodewalker(root, true)
	files = nil
	_ = files
	again := heap()
	t.Logf("after walking the same tree again: %d KiB retained in total", (int64(again)-int64(before))/1024)

	// A copy of the tree under another root has different paths.
	other, err := os.MkdirTemp("", "cli2075-gocodewalker-heap-other-")
	require.NoError(t, err)
	defer os.RemoveAll(other)
	for i := range 2000 {
		populateFolder(t, filepath.Join(other, fmt.Sprintf("d%04d", i)), 25)
	}
	require.NoError(t, os.WriteFile(filepath.Join(other, ".gitignore"), []byte("*.log\nbuild/\n"), 0o644))
	files = rawGocodewalker(other, true)
	files = nil
	_ = files
	third := heap()
	t.Logf("after walking a second tree with different paths: %d KiB retained in total", (int64(third)-int64(before))/1024)
}

// TestGocodewalkerLargeRepositoryClasses compares the adapter with git ls-files on the repository in
// CLI2075_LARGE_REPO and sorts every difference into a class. It skips unless the variable is set.
func TestGocodewalkerLargeRepositoryClasses(t *testing.T) {
	repo := os.Getenv("CLI2075_LARGE_REPO")
	if repo == "" {
		t.Skip("CLI2075_LARGE_REPO not set")
	}
	isolateGit(t)

	oracle := largeRepoOracleListing(t, repo)
	got := normalizeScenarioResult(t, repo, gocodewalkerScan(repo, nopLogger()))
	missing, unexpected := diffPaths(oracle, got)

	classes := map[string][]string{}
	for _, p := range missing {
		info, err := os.Lstat(filepath.Join(repo, filepath.FromSlash(p)))
		switch {
		case err != nil:
			classes["only in git: listed by the index but gone from disk"] = append(classes["only in git: listed by the index but gone from disk"], p)
		case info.Mode()&os.ModeSymlink != 0:
			classes["only in git: symlink"] = append(classes["only in git: symlink"], p)
		case !info.Mode().IsRegular():
			classes["only in git: not a regular file"] = append(classes["only in git: not a regular file"], p)
		default:
			classes["only in git: other"] = append(classes["only in git: other"], p)
		}
	}
	for p, source := range ignoreSources(t, repo, unexpected) {
		class := "only in adapter: ignored by " + ignoreSourceClass(source)
		classes[class] = append(classes[class], p)
	}

	t.Logf("oracle lists %d files, adapter returned %d; %d only in git, %d only in adapter", len(oracle), len(got), len(missing), len(unexpected))
	names := make([]string, 0, len(classes))
	for name := range classes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		paths := classes[name]
		sort.Strings(paths)
		t.Logf("class %q: %d files, first 10: %s", name, len(paths), firstN(paths))
	}
}

// ignoreSources asks git which ignore file excludes each path, by file name ("" when none does).
func ignoreSources(t *testing.T, repo string, paths []string) map[string]string {
	t.Helper()

	sources := make(map[string]string, len(paths))
	if len(paths) == 0 {
		return sources
	}

	cmd := exec.Command("git", "check-ignore", "-v", "-z", "--no-index", "--stdin")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), scenarioGitEnv(nil)...)
	cmd.Stdin = strings.NewReader(strings.Join(paths, "\x00") + "\x00")
	// Exit status 1 means no path matched, which is a valid answer here.
	output, _ := cmd.Output()

	fields := strings.Split(string(output), "\x00")
	for i := 0; i+3 < len(fields); i += 4 {
		sources[fields[i+3]] = fields[i]
	}
	for _, p := range paths {
		if _, ok := sources[p]; !ok {
			sources[p] = "no rule git can name (check-ignore reported none)"
		}
	}

	return sources
}

func ignoreSourceClass(source string) string {
	switch {
	case source == ".git/info/exclude":
		return ".git/info/exclude"
	case filepath.Base(source) == ".gitignore":
		return "a .gitignore file"
	default:
		return source
	}
}
