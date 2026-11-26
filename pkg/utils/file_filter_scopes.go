package utils

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	gitignore "github.com/sabhiram/go-gitignore"
)

// scopedMatcher gives the same result as gitignore.CompileIgnoreLines(globs...).MatchesPath, but
// evaluates each path only against the globs that can match it. It is safe for concurrent use.
// go-gitignore matches a pattern only where its literal leading directories appear in the path: at the
// start if the pattern starts with "/", else at the start or after any "/" (a superset, as go-gitignore
// anchors some of these too). With many nested ignore files, most globs cannot match a given path. Each
// glob is compiled once, and folders with the same set of scopes share one list of applicable glob indices.
type scopedMatcher struct {
	globs      []scopedGlob
	scopes     []string
	mu         sync.RWMutex
	byDir      map[string][]int
	byScopeSet map[string][]int
}

type scopedGlob struct {
	matcher    *gitignore.GitIgnore
	negated    bool
	scopeIndex int // index into scopes, -1 when the glob can match any path
}

// globLiteralEnd lists the characters at which a glob stops being matched literally by
// go-gitignore: glob syntax, escapes, and regex metacharacters that go-gitignore passes through.
const globLiteralEnd = `*?[\+()}$^`

func newScopedMatcher(globs []string) *scopedMatcher {
	m := &scopedMatcher{
		globs:      make([]scopedGlob, len(globs)),
		byDir:      map[string][]int{},
		byScopeSet: map[string][]int{},
	}

	indexOfScope := map[string]int{}
	for i, glob := range globs {
		lines := []string{glob}
		_, negated := globPattern(glob)
		if negated {
			lines = []string{matchEveryPath, glob}
		}
		m.globs[i] = scopedGlob{matcher: gitignore.CompileIgnoreLines(lines...), negated: negated, scopeIndex: -1}

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

// matchEveryPath compiles to "^(|.*/)|(|/.*)$" and matches every path; "*" misses some paths with newlines.
const matchEveryPath = "|"

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
		if glob := m.globs[applicable[i]]; glob.matcher.MatchesPath(slashPath) != glob.negated {
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
