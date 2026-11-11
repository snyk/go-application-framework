package utils

import (
	"math/rand"
	"strings"
	"testing"

	gitignore "github.com/sabhiram/go-gitignore"
	"github.com/stretchr/testify/assert"
)

func TestScopeOfGlob(t *testing.T) {
	tests := []struct {
		glob     string
		expected globScope
	}{
		{glob: "/repo/a/**/foo/**", expected: globScope{dir: "/repo/a/", anchored: true}},
		{glob: "!/repo/a/**/*.txt", expected: globScope{dir: "/repo/a/", anchored: true}},
		{glob: "/repo/a/file.txt", expected: globScope{dir: "/repo/a/", anchored: true}},
		{glob: "/repo/a\\(b\\)/**/foo", expected: globScope{dir: "/repo/", anchored: true}},
		{glob: "/repo/a(b)/**/foo", expected: globScope{dir: "/repo/", anchored: true}},
		{glob: "/repo/a+b/foo", expected: globScope{dir: "/repo/", anchored: true}},
		{glob: "/repo/a?/foo", expected: globScope{dir: "/repo/", anchored: true}},
		{glob: "/repo/[ab]/foo", expected: globScope{dir: "/repo/", anchored: true}},
		{glob: "repo/a/**/foo", expected: globScope{dir: "repo/a/", anchored: false}},
		{glob: "/foo", expected: globScope{}},
		{glob: "/**/.git/**", expected: globScope{}},
		{glob: "**/.git/**", expected: globScope{}},
		{glob: "foo", expected: globScope{}},
		{glob: "#gitignore:/repo/a/foo", expected: globScope{}},
		{glob: "/repo/a/bin/**", expected: globScope{dir: "/repo/a/", anchored: true}},
		{glob: "repo/bin/**", expected: globScope{dir: "repo/", anchored: false}},
		{glob: "/repo/a/**/**", expected: globScope{dir: "/repo/a/", anchored: true}},
		{glob: " /repo/a/foo ", expected: globScope{dir: "/repo/a/", anchored: true}},
		{glob: "/repo/a/foo\r", expected: globScope{dir: "/repo/a/", anchored: true}},
		{glob: "!!/repo/a/foo", expected: globScope{}},
	}

	for _, tt := range tests {
		t.Run(tt.glob, func(t *testing.T) {
			assert.Equal(t, tt.expected, scopeOfGlob(tt.glob))
		})
	}
}

func TestScopedMatcher_matchesUnscopedMatcher(t *testing.T) {
	tests := []struct {
		name  string
		globs []string
		paths []string
	}{
		{
			name: "absolute root",
			globs: []string{
				"**/.git/**",
				"/repo/**/*.tfvars",
				"!/repo/**/*.tfvars.example",
				"/repo/**/.terragrunt-cache/**",
				"/repo/**/.terragrunt-cache",
				"/repo/a/**/*.java",
				"!/repo/a/**/keep.java",
				"/repo/a/b/**/*.js",
				"!/repo/a/b/c/**/*.txt",
				"/repo/a(b)/x/**",
				"/repo/a+b/y/**",
				"/repo/stamps/s/.terragrunt-cache/h1/h2/**/*.tfvars",
				"!/repo/stamps/s/.terragrunt-cache/h1/h2/**/main.tf",
				"#gitignore:/repo/a/**/*.md",
				"relative/**/*.log",
				"/repo/bin/**",
				" /repo/padded/** ",
			},
			paths: []string{
				"/repo/main.go",
				"/repo/.git/config",
				"/repo/x.tfvars",
				"/repo/x.tfvars.example",
				"/repo/a/Foo.java",
				"/repo/a/keep.java",
				"/repo/a/b/app.js",
				"/repo/a/b/c/readme.txt",
				"/repo/a/b/c/app.js",
				"/repo/a(b)/x/y.go",
				"/repo/ab/x/y.go",
				"/repo/aab/y/z.go",
				"/repo/stamps/s/.terragrunt-cache/h1/h2/main.tf",
				"/repo/stamps/s/.terragrunt-cache/h1/h2/vars.tfvars",
				"/repo/stamps/s/.terragrunt-cache/h1/h2/vars.tfvars.example",
				"/repo/stamps/t/.terragrunt-cache/h1/h2/main.tf",
				"/repo/a/doc.md",
				"/repo/relative/deep/x.log",
				"/other/relative/x.log",
				"/repo/bin",
				"/repo/bin/tool",
				"/repo/padded/x.go",
			},
		},
		{
			name: "relative root",
			globs: []string{
				"**/.git/**",
				"**/*.tfvars",
				"!**/*.tfvars.example",
				"**/.terragrunt-cache/**",
				"a/**/*.java",
				"!a/**/keep.java",
				"a/b/**/*.js",
				"!a/b/c/**/*.txt",
				"stamps/s/.terragrunt-cache/h1/h2/**/*.tfvars",
				"!stamps/s/.terragrunt-cache/h1/h2/**/main.tf",
				"bin/**",
			},
			paths: []string{
				"main.go",
				"x.tfvars",
				"x.tfvars.example",
				"a/Foo.java",
				"a/keep.java",
				"z/a/Foo.java",
				"z/a/keep.java",
				"za/Foo.java",
				"a/b/app.js",
				"q/a/b/app.js",
				"a/b/c/readme.txt",
				"q/a/b/c/readme.txt",
				"stamps/s/.terragrunt-cache/h1/h2/main.tf",
				"x/stamps/s/.terragrunt-cache/h1/h2/main.tf",
				"stamps/s/.terragrunt-cache/h1/h2/vars.tfvars",
				"stamps/t/.terragrunt-cache/h1/h2/main.tf",
				"bin",
				"q/bin",
				"q/bin/tool",
			},
		},
	}

	for _, tt := range tests {
		expected := gitignore.CompileIgnoreLines(tt.globs...)
		actual := newScopedMatcher(tt.globs)

		for _, path := range tt.paths {
			t.Run(tt.name+"/"+path, func(t *testing.T) {
				assert.Equal(t, expected.MatchesPath(path), actual.MatchesPath(path))
			})
		}
	}
}

func TestScopedMatcher_matchesUnscopedMatcherForGeneratedGlobs(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	names := []string{"a", "b", "bin", "foo", "x.txt", "a(b)", "a+b", "c d", "*.txt", "?", "[ab]", "**", "a/b", "foo/**", "**/foo"}
	bases := []string{".", "/repo", "/repo/a", "repo/a", " a", "a ", "/r(x)", "/r+x", "//srv/share"}
	pick := func(s []string) string { return s[r.Intn(len(s))] }

	for i := 0; i < 2000; i++ {
		var globs []string
		for range 1 + r.Intn(6) {
			rule := pick(names)
			switch r.Intn(4) {
			case 0:
				rule = "/" + rule
			case 1:
				rule += "/"
			case 2:
				rule = "!" + rule
			}
			globs = append(globs, parseIgnoreRuleToGlobs(rule, pick(bases), defaultInvalidRules, r.Intn(2) == 0)...)
		}

		expected := gitignore.CompileIgnoreLines(globs...)
		actual := newScopedMatcher(globs)
		for range 20 {
			parts := []string{}
			if base := pick(bases); base != "." {
				parts = append(parts, base)
			}
			for range 1 + r.Intn(4) {
				parts = append(parts, strings.Trim(pick(names), "/*?[]!"))
			}
			path := strings.Join(parts, "/")
			if expected.MatchesPath(path) != actual.MatchesPath(path) {
				t.Fatalf("path %q, globs %q: expected %v", path, globs, expected.MatchesPath(path))
			}
		}
	}
}
