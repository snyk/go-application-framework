package utils

import (
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// scopedMatcher gives the same result as gitignore.CompileIgnoreLines(globs...).MatchesPath, but
// evaluates each path only against the globs that can match it. It is safe for concurrent use.
// go-gitignore matches a pattern only where its literal leading directories appear in the path: at the
// start if the pattern starts with "/", else at the start or after any "/" (a superset, as go-gitignore
// anchors some of these too). With many nested ignore files, most globs cannot match a given path. Each
// glob is compiled once, when a path first needs it, and folders with the same set of scopes share one
// list of applicable glob indices.
// A regular expression only runs on paths that contain all literals it requires.
type scopedMatcher struct {
	globs      []scopedGlob
	scopes     []string
	mu         sync.RWMutex
	byDir      map[string][]int
	byScopeSet map[string][]int
}

type scopedGlob struct {
	regexp     func() *regexp.Regexp // nil result when go-gitignore drops the glob
	required   []string              // literals that every path the glob matches contains
	negated    bool
	scopeIndex int // index into scopes, -1 when the glob can match any path
}

// globLiteralEnd lists the characters at which a glob stops being matched literally by go-gitignore: glob
// syntax, escapes, regex metacharacters it passes through, and U+FFFD, which also matches invalid UTF-8.
const globLiteralEnd = `*?[\+()}$^` + "\uFFFD"

func newScopedMatcher(globs []string) *scopedMatcher {
	m := &scopedMatcher{
		globs:      make([]scopedGlob, len(globs)),
		byDir:      map[string][]int{},
		byScopeSet: map[string][]int{},
	}

	indexOfScope := map[string]int{}
	for i, glob := range globs {
		expr, negated := globRegexp(glob)
		m.globs[i] = scopedGlob{regexp: lazyRegexp(expr), required: requiredLiterals(expr), negated: negated, scopeIndex: -1}

		scope := scopeOfGlob(glob)
		if scope == "" {
			continue
		}
		index, ok := indexOfScope[scope]
		if !ok {
			index = len(m.scopes)
			indexOfScope[scope] = index
			m.scopes = append(m.scopes, scope)
		}
		m.globs[i].scopeIndex = index
	}
	return m
}

// globPattern trims glob as go-gitignore does before it compiles a line. Comments give an empty pattern.
func globPattern(glob string) (pattern string, negated bool) {
	pattern = strings.TrimRight(glob, "\r")
	if strings.HasPrefix(pattern, "#") {
		return "", false
	}
	return strings.CutPrefix(strings.Trim(pattern, " "), "!")
}

// scopeOfGlob mirrors how go-gitignore turns a line into a regular expression. It returns the literal
// leading directories of glob, ending in "/", or "" whenever they are not required literally.
// TestScopedMatcher_MatchesPlainGitignoreForGeneratedGlobs checks this against go-gitignore on upgrades.
func scopeOfGlob(glob string) string {
	pattern, _ := globPattern(glob)
	// go-gitignore strips one more leading "#" or "!", and compiles a leading "/**/" to an optional
	// prefix. "|", "{" and its "#$~" placeholder for "*" reach the regular expression unescaped, where
	// they can make the leading directories optional.
	if strings.HasPrefix(pattern, "#") || strings.HasPrefix(pattern, "!") || strings.HasPrefix(pattern, "/**/") ||
		strings.ContainsAny(pattern, "|{") || strings.Contains(pattern, "#$~") {
		return ""
	}

	literalEnd := strings.IndexAny(pattern, globLiteralEnd)
	if literalEnd == -1 {
		literalEnd = len(pattern)
	}

	// go-gitignore compiles a "/**" that is not "/**/" to "(|/.*)", so "dir/**" also matches a file named "dir".
	if literalEnd > 0 && strings.HasPrefix(pattern[literalEnd-1:], "/**") && !strings.HasPrefix(pattern[literalEnd-1:], "/**/") {
		literalEnd--
	}
	return pattern[:strings.LastIndex(pattern[:literalEnd], "/")+1]
}

// scopeAppliesTo reports whether a path in dir, which ends in "/" or is empty, can match a glob with this scope.
func scopeAppliesTo(scope, dir string) bool {
	if strings.HasPrefix(scope, "/") {
		// go-gitignore compiles a leading "/" to "^(|/)", so the pattern also matches without it.
		return strings.HasPrefix(dir, scope) || strings.HasPrefix(dir, scope[1:])
	}
	return strings.HasPrefix(dir, scope) || strings.Contains(dir, "/"+scope)
}

func (m *scopedMatcher) MatchesPath(path string) bool {
	slashPath := filepath.ToSlash(path)
	applicable := m.globIndicesFor(slashPath[:strings.LastIndex(slashPath, "/")+1])
	// go-gitignore's result is decided by the last glob that matches the path.
	for i := len(applicable) - 1; i >= 0; i-- {
		if glob := &m.globs[applicable[i]]; glob.matches(slashPath) {
			return !glob.negated
		}
	}
	return false
}

func (m *scopedMatcher) globIndicesFor(dir string) []int {
	m.mu.RLock()
	applicable, ok := m.byDir[dir]
	m.mu.RUnlock()
	if ok {
		return applicable
	}

	inScope := make([]bool, len(m.scopes))
	var key strings.Builder
	for i, scope := range m.scopes {
		if scopeAppliesTo(scope, dir) {
			inScope[i] = true
			key.WriteString(strconv.Itoa(i))
			key.WriteByte(',')
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	applicable, ok = m.byScopeSet[key.String()]
	if !ok {
		for i, glob := range m.globs {
			if glob.scopeIndex < 0 || inScope[glob.scopeIndex] {
				applicable = append(applicable, i)
			}
		}
		m.byScopeSet[key.String()] = applicable
	}
	m.byDir[dir] = applicable
	return applicable
}

func (g *scopedGlob) matches(path string) bool {
	for _, literal := range g.required {
		if !strings.Contains(path, literal) {
			return false
		}
	}
	compiled := g.regexp()
	return compiled != nil && compiled.MatchString(path)
}

// requiredLiterals returns the literals at the top level of expr, longest first. Every string that
// expr matches contains all of them. Literals with U+FFFD are left out, as expr matches U+FFFD on
// invalid UTF-8 bytes.
func requiredLiterals(expr string) []string {
	parsed, err := syntax.Parse(expr, syntax.Perl)
	if err != nil || parsed.Op != syntax.OpConcat {
		return nil
	}
	var literals []string
	for _, sub := range parsed.Sub {
		if sub.Op == syntax.OpLiteral && sub.Flags&syntax.FoldCase == 0 && !slices.Contains(sub.Rune, utf8.RuneError) {
			literals = append(literals, string(sub.Rune))
		}
	}
	slices.SortStableFunc(literals, func(a, b string) int { return len(b) - len(a) })
	return literals
}

// lazyRegexp defers compiling expr, as most globs of a large tree never get past the scope and literal
// checks. Like go-gitignore, it gives nil for an empty or invalid expression. Concurrent callers share
// one compilation.
func lazyRegexp(expr string) func() *regexp.Regexp {
	return sync.OnceValue(func() *regexp.Regexp {
		if expr == "" {
			return nil
		}
		compiled, err := regexp.Compile(expr)
		if err != nil {
			return nil
		}
		return compiled
	})
}
