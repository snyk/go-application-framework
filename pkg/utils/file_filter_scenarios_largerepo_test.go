//go:build unix

package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Large real repositories. A clone is generated in place with files that its own .gitignore rules
// ignore, then every implementation is compared with git ls-files on it. The generator only adds
// untracked paths, and refuses a repository that already has any untracked or ignored entry.
//
//	CLI2075_LARGE_REPO=<clone> CLI2075_LARGE_MANIFEST=<file> go test ./pkg/utils -run '^TestGenerateLargeRepositoryUntracked$' -count=1 -v
//	CLI2075_LARGE_REPO=<clone> CLI2075_LARGE_MANIFEST=<file> go test ./pkg/utils -run '^TestLargeRepositoryDiff$' -count=1 -v
//	CLI2075_LARGE_REPO=<clone> go test ./pkg/utils -run '^$' -bench '^BenchmarkLargeRepository$' -benchmem -benchtime=3x -v

const (
	largeRepoMaxEntriesPerIgnoreFile = 5
	largeRepoMaxGeneratedFiles       = 20000
	largeRepoKeepEveryNthFolder      = 20
	largeRepoNodeModulesFolders      = 500
	largeRepoNodeModulesFilesPerDir  = 100
	largeRepoGeneratedNodeModules    = "node_modules"
)

// Patterns the generator reads: a single name, a name with a trailing slash, *.ext, and dir/*.ext.
var (
	largeRepoExtPattern    = regexp.MustCompile(`^\*\.([^*/]+)$`)
	largeRepoDirExtPattern = regexp.MustCompile(`^/?([^*/]+(?:/[^*/]+)*)/\*\.([^*/]+)$`)
)

type largeRepoRuleKind int

const (
	largeRepoRuleFile         largeRepoRuleKind = iota // name or /name: one file
	largeRepoRuleFolder                                // name/: a folder with three files
	largeRepoRuleExtension                             // *.ext: generated-N.ext
	largeRepoRuleDirExtension                          // dir/*.ext: dir/generated-N.ext
)

type largeRepoRule struct {
	kind largeRepoRuleKind
	// dir is the folder the file or folder is created in, relative to the .gitignore's folder.
	dir string
	// name is the file or folder name for file and folder rules.
	name string
	// ext is the extension for the two *.ext rules.
	ext string
}

// planLargeRepoRule decides what a pattern generates. An empty reason means the rule is supported.
func planLargeRepoRule(pattern string) (largeRepoRule, string) {
	switch {
	case strings.HasPrefix(pattern, "!"):
		return largeRepoRule{}, "negation"
	case strings.Contains(pattern, "**"):
		return largeRepoRule{}, "double-star"
	case strings.Contains(pattern, "["):
		return largeRepoRule{}, "bracket"
	case strings.Contains(pattern, "?"):
		return largeRepoRule{}, "question-mark"
	case strings.Contains(pattern, `\`):
		return largeRepoRule{}, "backslash"
	}

	if folder, ok := strings.CutSuffix(pattern, "/"); ok {
		name := strings.TrimPrefix(folder, "/")
		if name == "" || strings.ContainsAny(name, "*/") {
			return largeRepoRule{}, "unsupported form"
		}

		return largeRepoRule{kind: largeRepoRuleFolder, name: name}, ""
	}

	if m := largeRepoExtPattern.FindStringSubmatch(pattern); m != nil {
		return largeRepoRule{kind: largeRepoRuleExtension, ext: m[1]}, ""
	}
	if m := largeRepoDirExtPattern.FindStringSubmatch(pattern); m != nil {
		return largeRepoRule{kind: largeRepoRuleDirExtension, dir: m[1], ext: m[2]}, ""
	}

	name := strings.TrimPrefix(pattern, "/")
	if name == "" || strings.Contains(name, "*") || strings.Contains(name, "/") {
		return largeRepoRule{}, "unsupported form"
	}

	return largeRepoRule{kind: largeRepoRuleFile, name: name}, ""
}

type largeRepoGeneration struct {
	gitignoreFiles      int
	gitignoreWithOutput int
	entries             int
	ruleFiles           []string
	keepFiles           []string
	nodeModulesFiles    []string
	skipped             map[string]int
}

// generatorState tracks the repository as it is written, so every generated path is checked against
// tracked paths and against files created earlier in the same run.
type generatorState struct {
	tb      testing.TB
	root    string
	tracked map[string]bool
	dirs    map[string]bool
	out     *largeRepoGeneration
}

func (g *generatorState) taken(rel string) bool {
	if g.tracked[rel] || g.dirs[rel] {
		return true
	}
	_, err := os.Lstat(filepath.Join(g.root, filepath.FromSlash(rel)))

	return err == nil
}

func (g *generatorState) writeEmpty(rel string) {
	g.tb.Helper()

	full := filepath.Join(g.root, filepath.FromSlash(rel))
	require.NoError(g.tb, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(g.tb, os.WriteFile(full, nil, 0o644))
}

func (g *generatorState) markTrackedDirs() {
	for p := range g.tracked {
		for dir := path.Dir(p); dir != "." && dir != "/"; dir = path.Dir(dir) {
			g.dirs[dir] = true
		}
	}
}

// generateLargeRepoUntracked writes the files that the repository's own rules ignore. It returns the
// generated paths, split by what they are for, so the diff can check each group separately.
func generateLargeRepoUntracked(tb testing.TB, root string) largeRepoGeneration {
	tb.Helper()

	requireCleanClone(tb, root)

	listed := runScenarioGit(tb, root, nil, "ls-files", "-z")
	g := &generatorState{
		tb:      tb,
		root:    root,
		tracked: map[string]bool{},
		dirs:    map[string]bool{},
		out:     &largeRepoGeneration{skipped: map[string]int{}},
	}
	for _, p := range strings.Split(listed, "\x00") {
		if p != "" {
			g.tracked[p] = true
		}
	}
	g.markTrackedDirs()

	var ignoreFiles []string
	for p := range g.tracked {
		if path.Base(p) == ".gitignore" {
			ignoreFiles = append(ignoreFiles, p)
		}
	}
	slices.Sort(ignoreFiles)
	g.out.gitignoreFiles = len(ignoreFiles)

	// A keep file goes in every Nth folder that has a .gitignore. When a rule covers the candidate
	// (a folder whose .gitignore is just "*"), the next folder is tried instead.
	nextKeep := 0
	keepCount := 0
	for i, ignoreFile := range ignoreFiles {
		g.generateFromIgnoreFile(ignoreFile)
		if i >= nextKeep && g.writeKeepFile(path.Dir(ignoreFile), keepCount+1) {
			keepCount++
			nextKeep = i + largeRepoKeepEveryNthFolder
		}
	}

	g.writeNodeModules()

	return *g.out
}

func requireCleanClone(tb testing.TB, root string) {
	tb.Helper()

	status := runScenarioGit(tb, root, nil, "status", "--porcelain", "--ignored")
	require.Empty(tb, status, "the generator only runs on a clone with no untracked or ignored entries")
}

func (g *generatorState) generateFromIgnoreFile(ignoreFile string) {
	g.tb.Helper()

	dir := path.Dir(ignoreFile)
	if dir == "." {
		dir = ""
	}
	content, err := os.ReadFile(filepath.Join(g.root, filepath.FromSlash(ignoreFile)))
	require.NoError(g.tb, err)

	entries := 0
	counter := 0
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		pattern := strings.TrimRight(scanner.Text(), " \t\r")
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}

		rule, reason := planLargeRepoRule(pattern)
		if reason != "" {
			g.out.skipped[reason]++
			continue
		}
		if entries == largeRepoMaxEntriesPerIgnoreFile {
			g.out.skipped["per-file cap"]++
			continue
		}
		need := 1
		if rule.kind == largeRepoRuleFolder {
			need = 3
		}
		if len(g.out.ruleFiles)+len(g.out.keepFiles)+need > largeRepoMaxGeneratedFiles {
			g.out.skipped["overall file cap"]++
			continue
		}

		counter++
		if g.writeRule(dir, rule, counter) {
			entries++
		}
	}
	require.NoError(g.tb, scanner.Err())

	if entries > 0 {
		g.out.gitignoreWithOutput++
		g.out.entries += entries
	}
}

// writeRule creates what one rule generates. It reports false, and counts a skip, when the path is
// already taken.
func (g *generatorState) writeRule(dir string, rule largeRepoRule, n int) bool {
	g.tb.Helper()

	switch rule.kind {
	case largeRepoRuleFile:
		rel := path.Join(dir, rule.name)
		if g.taken(rel) {
			g.out.skipped["path taken"]++
			return false
		}
		g.writeEmpty(rel)
		g.out.ruleFiles = append(g.out.ruleFiles, rel)

	case largeRepoRuleFolder:
		folder := path.Join(dir, rule.name)
		if g.taken(folder) {
			g.out.skipped["path taken"]++
			return false
		}
		for i := 1; i <= 3; i++ {
			rel := path.Join(folder, fmt.Sprintf("generated-%d.txt", i))
			g.writeEmpty(rel)
			g.out.ruleFiles = append(g.out.ruleFiles, rel)
		}

	case largeRepoRuleExtension:
		rel := path.Join(dir, fmt.Sprintf("generated-%d.%s", n, rule.ext))
		if g.taken(rel) {
			g.out.skipped["path taken"]++
			return false
		}
		g.writeEmpty(rel)
		g.out.ruleFiles = append(g.out.ruleFiles, rel)

	case largeRepoRuleDirExtension:
		folder := path.Join(dir, rule.dir)
		rel := path.Join(folder, fmt.Sprintf("generated-%d.%s", n, rule.ext))
		if g.tracked[folder] || g.taken(rel) {
			g.out.skipped["path taken"]++
			return false
		}
		g.writeEmpty(rel)
		g.out.ruleFiles = append(g.out.ruleFiles, rel)
	}

	return true
}

// writeKeepFile adds a file that no rule ignores, so an implementation that ignores too much drops
// it. It reports false, writing nothing, when the path is taken or a rule would ignore it.
func (g *generatorState) writeKeepFile(dir string, n int) bool {
	g.tb.Helper()

	rel := path.Join(dir, fmt.Sprintf("keep-untracked-%d.txt", n))
	if g.taken(rel) {
		g.out.skipped["path taken"]++
		return false
	}
	if g.ignoredByGit(rel) {
		g.out.skipped["keep file ignored by a rule"]++
		return false
	}
	g.writeEmpty(rel)
	g.out.keepFiles = append(g.out.keepFiles, rel)

	return true
}

// ignoredByGit asks git, not the generator's own parsing, because rules in parent folders and
// patterns such as a lone * decide it.
func (g *generatorState) ignoredByGit(rel string) bool {
	g.tb.Helper()

	cmd := exec.Command("git", "check-ignore", "-q", "--no-index", "--", rel)
	cmd.Dir = g.root
	cmd.Env = append(os.Environ(), scenarioGitEnv(nil)...)
	err := cmd.Run()
	if err == nil {
		return true
	}

	var exitErr *exec.ExitError
	require.ErrorAs(g.tb, err, &exitErr)
	require.Equal(g.tb, 1, exitErr.ExitCode(), "git check-ignore failed for %s", rel)

	return false
}

// writeNodeModules adds the pruning case at scale: an ignored folder with many files. The folder is
// excluded through .git/info/exclude, not a tracked .gitignore, so the ignore comes from a second
// source. It is not counted against the rule-file cap.
func (g *generatorState) writeNodeModules() {
	g.tb.Helper()

	require.False(g.tb, g.taken(largeRepoGeneratedNodeModules), "node_modules is already tracked or present")

	for pkg := range largeRepoNodeModulesFolders {
		for file := range largeRepoNodeModulesFilesPerDir {
			rel := path.Join(largeRepoGeneratedNodeModules, fmt.Sprintf("pkg%03d", pkg), fmt.Sprintf("m%03d.js", file))
			g.writeEmpty(rel)
			g.out.nodeModulesFiles = append(g.out.nodeModulesFiles, rel)
		}
	}

	excludePath := filepath.Join(g.root, ".git", "info", "exclude")
	existing, err := os.ReadFile(excludePath)
	require.NoError(g.tb, err)
	if !bytes.Contains(existing, []byte(largeRepoGeneratedNodeModules+"/")) {
		f, err := os.OpenFile(excludePath, os.O_APPEND|os.O_WRONLY, 0o644)
		require.NoError(g.tb, err)
		_, err = f.WriteString(largeRepoGeneratedNodeModules + "/\n")
		require.NoError(g.tb, err)
		require.NoError(g.tb, f.Close())
	}
}

// TestPlanLargeRepoRule pins which patterns the generator reads and which it skips.
func TestPlanLargeRepoRule(t *testing.T) {
	cases := []struct {
		pattern string
		want    largeRepoRule
		reason  string
	}{
		{pattern: "*.log", want: largeRepoRule{kind: largeRepoRuleExtension, ext: "log"}},
		{pattern: "*.min.js", want: largeRepoRule{kind: largeRepoRuleExtension, ext: "min.js"}},
		{pattern: "build", want: largeRepoRule{kind: largeRepoRuleFile, name: "build"}},
		{pattern: "/scratch.txt", want: largeRepoRule{kind: largeRepoRuleFile, name: "scratch.txt"}},
		{pattern: "dist/", want: largeRepoRule{kind: largeRepoRuleFolder, name: "dist"}},
		{pattern: "/dist/", want: largeRepoRule{kind: largeRepoRuleFolder, name: "dist"}},
		{pattern: "docs/*.md", want: largeRepoRule{kind: largeRepoRuleDirExtension, dir: "docs", ext: "md"}},
		{pattern: "/docs/*.md", want: largeRepoRule{kind: largeRepoRuleDirExtension, dir: "docs", ext: "md"}},
		{pattern: "!keep.log", reason: "negation"},
		{pattern: "**/tmp", reason: "double-star"},
		{pattern: "a/**/b", reason: "double-star"},
		{pattern: "*.[oa]", reason: "bracket"},
		{pattern: "file?.txt", reason: "question-mark"},
		{pattern: `esc\*`, reason: "backslash"},
		{pattern: "a/b", reason: "unsupported form"},
		{pattern: "foo*", reason: "unsupported form"},
		{pattern: "*.log/", reason: "unsupported form"},
		{pattern: "/", reason: "unsupported form"},
	}
	for _, tc := range cases {
		t.Run(tc.pattern, func(t *testing.T) {
			got, reason := planLargeRepoRule(tc.pattern)
			require.Equal(t, tc.reason, reason)
			if tc.reason == "" {
				require.Equal(t, tc.want, got)
			}
		})
	}
}

// TestGenerateLargeRepositoryUntracked writes the generated files into the repository named by
// CLI2075_LARGE_REPO and writes their paths to CLI2075_LARGE_MANIFEST. It skips unless both are set.
func TestGenerateLargeRepositoryUntracked(t *testing.T) {
	repo := os.Getenv("CLI2075_LARGE_REPO")
	manifest := os.Getenv("CLI2075_LARGE_MANIFEST")
	if repo == "" || manifest == "" {
		t.Skip("CLI2075_LARGE_REPO and CLI2075_LARGE_MANIFEST not set")
	}
	isolateGit(t)

	gen := generateLargeRepoUntracked(t, repo)
	writeLargeRepoManifest(t, manifest, gen)

	t.Logf("generator: %d .gitignore files, %d produced output, %d entries; created %d rule files, %d keep files, %d node_modules files",
		gen.gitignoreFiles, gen.gitignoreWithOutput, gen.entries, len(gen.ruleFiles), len(gen.keepFiles), len(gen.nodeModulesFiles))
	for reason, count := range gen.skipped {
		t.Logf("skipped %d patterns: %s", count, reason)
	}

	// A rule file that git lists is not ignored, so it is an ordinary untracked file. A keep file
	// that git hides means a rule covers it, which breaks its purpose.
	oracle := largeRepoOracleListing(t, repo)
	listed := intersectLargeRepoPaths(oracle, gen.ruleFiles)
	keepIgnored := subtractLargeRepoPaths(gen.keepFiles, oracle)
	t.Logf("rule files git does not ignore: %d, first 10: %s", len(listed), firstN(listed))
	t.Logf("keep files git ignores: %d, first 10: %s", len(keepIgnored), firstN(keepIgnored))
	require.Empty(t, keepIgnored, "a keep-untracked file is ignored by a rule; the keep check would be meaningless")
}

// writeLargeRepoManifest records one path per line, prefixed with its group, so the clean-up and
// the diff can check exactly what was generated.
func writeLargeRepoManifest(tb testing.TB, file string, gen largeRepoGeneration) {
	tb.Helper()

	var b strings.Builder
	for _, p := range gen.ruleFiles {
		fmt.Fprintf(&b, "rule\t%s\n", p)
	}
	for _, p := range gen.keepFiles {
		fmt.Fprintf(&b, "keep\t%s\n", p)
	}
	for _, p := range gen.nodeModulesFiles {
		fmt.Fprintf(&b, "node_modules\t%s\n", p)
	}
	require.NoError(tb, os.WriteFile(file, []byte(b.String()), 0o644))
}

type largeRepoManifest struct {
	rule, keep, nodeModules []string
}

func readLargeRepoManifest(tb testing.TB, file string) largeRepoManifest {
	tb.Helper()

	content, err := os.ReadFile(file)
	require.NoError(tb, err)

	var m largeRepoManifest
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		group, p, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		switch group {
		case "rule":
			m.rule = append(m.rule, p)
		case "keep":
			m.keep = append(m.keep, p)
		case "node_modules":
			m.nodeModules = append(m.nodeModules, p)
		}
	}

	return m
}

// TestLargeRepositoryDiff compares every implementation with git ls-files on CLI2075_LARGE_REPO. It
// also reports which generated files an implementation returned, and which keep files it dropped.
// Skips unless CLI2075_LARGE_REPO is set. The manifest is optional: without it only the diff runs.
func TestLargeRepositoryDiff(t *testing.T) {
	repo := os.Getenv("CLI2075_LARGE_REPO")
	if repo == "" {
		t.Skip("CLI2075_LARGE_REPO not set")
	}
	isolateGit(t)

	oracle := largeRepoOracleListing(t, repo)
	var manifest largeRepoManifest
	if file := os.Getenv("CLI2075_LARGE_MANIFEST"); file != "" {
		manifest = readLargeRepoManifest(t, file)
	}
	t.Logf("oracle git ls-files lists %d files; manifest: %d rule files, %d keep files, %d node_modules files",
		len(oracle), len(manifest.rule), len(manifest.keep), len(manifest.nodeModules))

	for _, impl := range scenarioImplementations {
		t.Run(impl.name, func(t *testing.T) {
			got := normalizeScenarioResult(t, repo, impl.run(t, repo, scenarioOptions{}))
			missing, unexpected := diffPaths(oracle, got)
			slices.Sort(missing)
			slices.Sort(unexpected)

			returnedRule := intersectLargeRepoPaths(got, manifest.rule)
			returnedNodeModules := intersectLargeRepoPaths(got, manifest.nodeModules)
			droppedKeep := subtractLargeRepoPaths(manifest.keep, got)

			t.Logf("DIFF %s: returned=%d only-in-oracle=%d only-in-impl=%d",
				impl.name, len(got), len(missing), len(unexpected))
			t.Logf("  only-in-oracle, first 10: %s", firstN(missing))
			t.Logf("  only-in-impl, first 10: %s", firstN(unexpected))
			t.Logf("  generated rule files returned: %d, first 10: %s", len(returnedRule), firstN(returnedRule))
			t.Logf("  node_modules files returned: %d", len(returnedNodeModules))
			t.Logf("  keep-untracked files dropped: %d, first 10: %s", len(droppedKeep), firstN(droppedKeep))
		})
	}
}

// largeRepoOracleListing is git ls-files --cached --others --exclude-standard, with the environment
// isolated the same way as the implementations.
func largeRepoOracleListing(tb testing.TB, dir string) []string {
	tb.Helper()

	output := runScenarioGit(tb, dir, nil, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	var listed []string
	for _, p := range strings.Split(output, "\x00") {
		if p != "" {
			listed = append(listed, p)
		}
	}
	slices.Sort(listed)

	return listed
}

func intersectLargeRepoPaths(got, paths []string) []string {
	set := make(map[string]bool, len(got))
	for _, p := range got {
		set[p] = true
	}
	var hits []string
	for _, p := range paths {
		if set[p] {
			hits = append(hits, p)
		}
	}

	return hits
}

func subtractLargeRepoPaths(paths, got []string) []string {
	set := make(map[string]bool, len(got))
	for _, p := range got {
		set[p] = true
	}
	var missing []string
	for _, p := range paths {
		if !set[p] {
			missing = append(missing, p)
		}
	}

	return missing
}

// BenchmarkLargeRepository times every implementation on CLI2075_LARGE_REPO, as the state of the
// repository is when the benchmark runs. A count that differs from git is logged, not failed: the
// diff test classifies it.
func BenchmarkLargeRepository(b *testing.B) {
	repo := os.Getenv("CLI2075_LARGE_REPO")
	if repo == "" {
		b.Skip("CLI2075_LARGE_REPO not set")
	}
	isolateGit(b)
	logCoreLimit(b)

	indexRead, entries := timeIndexRead(b, repo)
	wantFiles := len(largeRepoOracleListing(b, repo))
	b.Logf("%s: index read %s for %d entries; git ls-files lists %d files", filepath.Base(repo), indexRead, entries, wantFiles)

	for _, impl := range scenarioImplementations {
		b.Run(impl.name, func(b *testing.B) {
			b.ReportAllocs()

			var returned int
			cpuBefore := processCPUTime(b)
			b.ResetTimer()
			for range b.N {
				returned = len(impl.run(b, repo, scenarioOptions{}))
			}
			b.StopTimer()
			cpu := processCPUTime(b) - cpuBefore

			b.ReportMetric(float64(cpu)/1e6/float64(b.N), "cpu-ms/op")
			b.ReportMetric(float64(returned), "files")
			if returned != wantFiles {
				b.Logf("%s returned %d files, git ls-files lists %d", impl.name, returned, wantFiles)
			}
		})
	}
}
