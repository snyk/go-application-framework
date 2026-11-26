package utils

import (
	"math/rand/v2"
	"strings"
	"testing"

	gitignore "github.com/sabhiram/go-gitignore"
	"github.com/stretchr/testify/assert"
)

func TestScopeOfGlob(t *testing.T) {
	for glob, expected := range map[string]globScope{
		"/repo/a/**/foo/**":      {dir: "/repo/a/", anchored: true},
		"!/repo/a/**/*.txt":      {dir: "/repo/a/", anchored: true},
		"/repo/a\\(b\\)/**/foo":  {dir: "/repo/", anchored: true},
		"/repo/a+b/foo":          {dir: "/repo/", anchored: true},
		"/repo/[ab]/foo":         {dir: "/repo/", anchored: true},
		"repo/a/**/foo":          {dir: "repo/a/"},
		"/repo/a/bin/**":         {dir: "/repo/a/", anchored: true},
		" /repo/a/foo \r":        {dir: "/repo/a/", anchored: true},
		"/foo":                   {dir: "/", anchored: true},
		"foo":                    {},
		"/**/.git/**":            {},
		"#gitignore:/repo/a/foo": {},
		"!!/repo/a/foo":          {},
		"/repo/a/**/x|y":         {},
		"/repo/a/**/{0}b":        {},
		"/repo/a/#$~":            {},
	} {
		assert.Equal(t, expected, scopeOfGlob(glob), glob)
	}
}

func TestScopedMatcher_MatchesPlainGitignore(t *testing.T) {
	t.Parallel()
	globs := []string{
		"**/.git/**",
		"/repo/*/*.go",
		"/repo/**/*.tfvars",
		"!/repo/**/*.tfvars.example",
		"/repo/a/**/*.java",
		"!/repo/a/**/keep.java",
		"/repo/a/b/**/*.js",
		"!/repo/a/b/c/**/*.js",
		"/repo/a(b)/x/**",
		"#gitignore:/repo/a/**/*.md",
		"relative/**/*.log",
		"/repo/bin/**",
		" /repo/padded/** \r",
		"/repo/a/**/x|y",
	}
	paths := map[string]bool{
		"/repo/main.go":          false,
		"/repo/.git/config":      true,
		"/repo/x.tfvars.example": false,
		"/repo/a/z.java":         true,
		"/repo/a/keep.java":      false,
		"repo/a/z.java":          true, // an anchored glob also matches without the leading "/"
		"/repo/a/b/c/z.js":       false,
		"/repo/ab/x/z.go":        true, // "(b)" is a regular expression group
		"/repo/a/doc.md":         false,
		"/other/relative/z.log":  false,
		"/repo/bin":              true,
		"/repo/padded/z.go":      true,
		"/other/y":               true, // "x|y" is an alternation, "y" matches anywhere
		"/repo/\nd/\nz.go":       true, // "." in go-gitignore's expressions does not match "\n"
		"main.go":                false,
	}
	expected := gitignore.CompileIgnoreLines(globs...)
	actual := newScopedMatcher(globs)
	assert.Len(t, actual.globsFor("/repo/main/"), 9)

	for path, want := range paths {
		t.Run(path, func(t *testing.T) {
			// Parallel subtests share actual, so -race also checks concurrent use.
			t.Parallel()
			assert.Equal(t, want, expected.MatchesPath(path))
			assert.Equal(t, want, actual.MatchesPath(path))
		})
	}
}

func TestScopedMatcher_MatchesPlainGitignoreForGeneratedGlobs(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	names := []string{"a", "b", "ab", "bin", "foo", "x.txt", "a(b)", "a+b", "c d", "*.txt", "?", "[ab]", "**", "a/b", "foo/**", "foo/*/**", "**/foo", "a|b", "a/{0}b", "a#$~", "a\nb"}
	bases := []string{".", "/repo", "/repo/a", "repo/a", " a", "a ", "/r(x)", "/r+x", "//srv/share"}
	pick := func(s []string) string { return s[r.IntN(len(s))] }

	matched := 0
	for i := range 2000 {
		var globs []string
		for range 1 + r.IntN(6) {
			rule := pick(names)
			switch r.IntN(4) {
			case 0:
				rule = "/" + rule
			case 1:
				rule += "/"
			case 2:
				rule = "!" + rule
			}
			globs = append(globs, parseIgnoreRuleToGlobs(rule, pick(bases), defaultInvalidRules, i%2 == 0, i/2%2 == 0)...)
		}

		expected := gitignore.CompileIgnoreLines(globs...)
		actual := newScopedMatcher(globs)
		for range 20 {
			var parts []string
			if base := pick(bases); base != "." {
				parts = append(parts, base)
			}
			for range 1 + r.IntN(4) {
				parts = append(parts, strings.Trim(pick(names), "/*?[]!"))
			}
			path := strings.Join(parts, "/")
			got, want := actual.MatchesPath(path), expected.MatchesPath(path)
			if got != want {
				t.Fatalf("path %q, globs %q: got %v, want %v", path, globs, got, want)
			}
			if want {
				matched++
			}
		}
	}
	assert.Positive(t, matched)
}
