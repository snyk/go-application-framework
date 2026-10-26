package utils

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	gitignore "github.com/sabhiram/go-gitignore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The ignore matcher must be bit-for-bit compatible with go-gitignore, which it replaces.
// These tests compare both implementations instead of asserting on expected values.

var ignoreMatcherTestRules = []string{
	"*.o", "*.log", "!keep.log", "build/", "/dist", "/out/", "**/node_modules/**", "foo/**", "**/bar",
	"a/**/b", "docs/*.html", "*.tmp", "!important.tmp", ".cache", "/x/y/z", "cache[^S]", "file?.txt",
	"(paren)", "build (old)/", "a+b", "$HOME", "#comment", "\\#hash", "\\!bang", "  ", "", "/", ".",
	"**", "/**/deep", "trailing/**", "x\r", "!", "*", "**/*.min.js", "lib/**/*.c", "[abc].go",
}

var ignoreMatcherTestDirs = []string{
	"/repo", "/repo/sub", "/repo/sub/deep", "/repo/other", "repo", "repo/sub", "C:/repo", "C:/repo/sub",
	"//server/share/repo", "/repo/build (old)", "/repo/a+b", "/repo/we$ird",
}

var ignoreMatcherTestPaths = []string{
	"main.o", "keep.log", "app.log", "build/out.bin", "dist", "dist/a.js", "out/x", "node_modules/x/y.js",
	"foo/a/b", "x/bar", "bar", "a/b", "a/x/y/b", "docs/i.html", "docs/p/i.html", "important.tmp", "t.tmp",
	".cache/z", "x/y/z", "cacheA", "cacheS", "file1.txt", "fileX.txt", "(paren)", "build (old)/f", "a+b",
	"$HOME", "#hash", "!bang", "deep", "s/deep", "trailing/q", "lib/x/y.c", "a.go", "d.go", "x.min.js",
	".git/HEAD", "src/.git/config", "sub/keep.log", "sub/deep/main.o", "other/file.txt",
}

func compareMatchers(tb testing.TB, globs []string, paths []string) {
	tb.Helper()
	want := gitignore.CompileIgnoreLines(globs...)
	got := compileIgnoreMatcher(globs...)
	for _, p := range paths {
		if want.MatchesPath(p) != got.MatchesPath(p) {
			tb.Fatalf("mismatch for %q: go-gitignore=%v ignoreMatcher=%v\nglobs:\n%s",
				p, want.MatchesPath(p), got.MatchesPath(p), strings.Join(globs, "\n"))
		}
	}
}

func buildTestGlobs(dirs []string, rules []string, enableMetacharacterFix bool) []string {
	globs := []string{"**/.git/**"}
	for _, dir := range dirs {
		globs = append(globs, parseIgnoreFile([]byte(strings.Join(rules, "\n")), dir, enableMetacharacterFix)...)
	}
	return globs
}

func buildTestPaths(dirs []string) []string {
	var paths []string
	for _, dir := range dirs {
		for _, p := range ignoreMatcherTestPaths {
			paths = append(paths, dir+"/"+p)
		}
	}
	return append(paths, ignoreMatcherTestPaths...)
}

func Test_ignoreMatcher_MatchesGoGitignore(t *testing.T) {
	paths := buildTestPaths(ignoreMatcherTestDirs)

	for _, fix := range []bool{true, false} {
		t.Run(fmt.Sprintf("metacharacterFix=%v", fix), func(t *testing.T) {
			// rules from every directory, as GetRules produces them
			compareMatchers(t, buildTestGlobs(ignoreMatcherTestDirs, ignoreMatcherTestRules, fix), paths)

			// raw rules without a base directory, as callers may pass them
			compareMatchers(t, ignoreMatcherTestRules, paths)
		})
	}
}

func Test_ignoreMatcher_MatchesGoGitignore_RandomRuleOrder(t *testing.T) {
	// order matters for negations, so shuffle rules and directories
	rnd := rand.New(rand.NewSource(1))
	paths := buildTestPaths(ignoreMatcherTestDirs)
	for i := 0; i < 200; i++ {
		rules := append([]string(nil), ignoreMatcherTestRules...)
		rnd.Shuffle(len(rules), func(a, b int) { rules[a], rules[b] = rules[b], rules[a] })
		rules = rules[:1+rnd.Intn(len(rules))]
		dirs := append([]string(nil), ignoreMatcherTestDirs...)
		rnd.Shuffle(len(dirs), func(a, b int) { dirs[a], dirs[b] = dirs[b], dirs[a] })
		dirs = dirs[:1+rnd.Intn(len(dirs))]
		compareMatchers(t, buildTestGlobs(dirs, rules, rnd.Intn(2) == 0), paths)
	}
}

func Test_ignoreMatcher_SkipsPrefixedGitignoreRules(t *testing.T) {
	// trackedFileExclusionPredicate relies on prefixed .gitignore rules being treated as comments
	globs := []string{gitIgnoreGlobPrefix + "/repo/**/*.o", "/repo/**/*.log"}
	m := compileIgnoreMatcher(globs...)
	assert.False(t, m.MatchesPath("/repo/a.o"))
	assert.True(t, m.MatchesPath("/repo/a.log"))
}

func Test_ignoreMatcher_IndexesRulesByDirectory(t *testing.T) {
	m := compileIgnoreMatcher(buildTestGlobs([]string{"/repo/a", "/repo/b"}, []string{"*.o", "/build"}, true)...)
	require.Len(t, m.always, 1, "only the base-dir independent default rule should be evaluated for every path")
	assert.Len(t, m.anchored, 2)
}

func FuzzIgnoreMatcher(f *testing.F) {
	f.Add("*.o\n!keep.o\nbuild/", "/repo/sub", "/repo/sub/x/keep.o")
	f.Add("/a/**/b", "C:/repo", "C:/repo/a/x/b")
	f.Add("cache[^S]", "repo", "repo/cacheA")
	f.Fuzz(func(t *testing.T, rules string, dir string, path string) {
		globs := append([]string{"**/.git/**"}, parseIgnoreFile([]byte(rules), dir, true)...)
		globs = append(globs, strings.Split(rules, "\n")...)
		compareMatchers(t, globs, []string{path, dir + "/" + path, "/" + path})
	})
}
