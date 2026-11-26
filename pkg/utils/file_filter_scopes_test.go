package utils

import (
	"math/rand/v2"
	"strings"
	"testing"

	gitignore "github.com/sabhiram/go-gitignore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeOfGlob(t *testing.T) {
	for glob, expected := range map[string]string{
		"/repo/a/**/foo/**":      "/repo/a/",
		"!/repo/a/**/*.txt":      "/repo/a/",
		"/repo/a\\(b\\)/**/foo":  "/repo/",
		"/repo/a\uFFFDb/foo":     "/repo/",
		"/repo/[ab]/foo":         "/repo/",
		"repo/a/**/foo":          "repo/a/",
		"/repo/a/bin/**":         "/repo/a/",
		" /repo/a/foo \r":        "/repo/a/",
		"/foo":                   "/",
		"foo":                    "",
		"/**/.git/**":            "",
		"#gitignore:/repo/a/foo": "",
		"!!/repo/a/foo":          "",
		"!#/repo/a/foo":          "",
		"/repo/a/**/x|y":         "",
		"/repo/a/**/{0}b":        "",
		"/repo/a/#$~":            "",
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
		"/repo/a\uFFFDb/x",
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
		"/repo/(x",
	}
	paths := map[string]bool{
		"/repo/main.go":         false,
		"/repo/.git/config":     true,
		"/repo/a\xffb/x":        true, // regexps match U+FFFD on invalid UTF-8 bytes
		"/repo/a/z.java":        true,
		"/repo/a/keep.java":     false,
		"repo/a/z.java":         true, // an anchored glob also matches without the leading "/"
		"/repo/a/b/c/z.js":      false,
		"/repo/ab/x/z.go":       true, // "(b)" is a regular expression group
		"/repo/a/doc.md":        false,
		"/other/relative/z.log": false,
		"/repo/bin":             true,
		"/repo/padded/z.go":     true,
		"/other/y":              true,  // "x|y" is an alternation, "y" matches anywhere
		"/repo/\nd/\nz.go":      true,  // "." in go-gitignore's expressions does not match "\n"
		"/repo/(x":              false, // "(" without ")" does not compile, so go-gitignore drops the glob
		"main.go":               false,
	}
	expected := gitignore.CompileIgnoreLines(globs...)
	actual := newScopedMatcher(globs)
	assert.Equal(t, []string{"repo/a", ".java"}, actual.globs[4].required) // "/**/" in globs[4] compiles to "(/|/.+/)"
	assert.Nil(t, actual.globs[14].regexp, "go-gitignore drops globs[14], which does not compile")
	assert.Equal(t, []int{0, 1, 2, 3, 8, 9, 11, 12, 13, 14}, actual.globIndicesFor("/repo/main/"), "unscoped globs and globs scoped to /repo/")

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
			want, how := expected.MatchesPathHow(path)
			require.Equal(t, want, actual.MatchesPath(path), "path %q, globs %q", path, globs)
			if how != nil {
				expr, negated := globRegexp(how.Line)
				require.Equal(t, how.Pattern.String(), expr, "glob %q", how.Line)
				require.False(t, negated, "glob %q", how.Line)
			}
			if want {
				matched++
			}
		}
	}
	assert.Greater(t, matched, 1000)
}

func TestScopedMatcher_MatchesPlainGitignoreForEdgeGlobs(t *testing.T) {
	for _, globs := range [][]string{
		{"/a/**", "!"}, {"!"}, {"#/a/**", "  ", "\r", "/a"}, {"/a/**", "! /a/b", "!!a", "\\#b"},
		{"a\uFFFDb", "/r/a\uFFFDb/x"}, // regexps match U+FFFD on invalid UTF-8 bytes
	} {
		expected := gitignore.CompileIgnoreLines(globs...)
		actual := newScopedMatcher(globs)
		for _, path := range []string{"a", "/a", "/a/b", "/a/c", "!a", "#b", "/a/#b", "a\xffb", "/r/a\xffb/x"} {
			assert.Equal(t, expected.MatchesPath(path), actual.MatchesPath(path), "path %q, globs %q", path, globs)
		}
	}
	assert.True(t, newScopedMatcher([]string{"a\uFFFDb"}).MatchesPath("a\xffb"))
}

func TestRequiredLiterals(t *testing.T) {
	for expr, expected := range map[string][]string{
		`^(|/)repo/a/(|.*/)([^/]*)\.java(|/.*)$`: {"repo/a/", ".java"},
		`^(|.*/)foo(|/.*)$`:                      {"foo"},
		`^(|.*/)a|b(|/.*)$`:                      nil, // top level is an alternation, not a concatenation
		`^(|/)(x`:                                nil, // does not parse
		`^a(|.*/)\.java$`:                        {".java", "a"},
		`^(|.*/)(?i)foo(|/.*)$`:                  nil,
		`^(|.*/)a\x{FFFD}b(|/.*)$`:               nil,
	} {
		assert.Equal(t, expected, requiredLiterals(expr), expr)
	}
}
