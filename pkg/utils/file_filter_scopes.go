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
// go-gitignore can only match a pattern where its literal leading directories appear in the path: at
// the start when the pattern starts with "/", or at the start or after any "/" otherwise. With many
// nested ignore files, most globs therefore cannot match a given path. Each glob is compiled once, and
// folders with the same set of scopes share one list of applicable globs.
type scopedMatcher struct {
	globs      []scopedGlob
	scopes     []globScope
	mu         sync.RWMutex
	byDir      map[string][]int
	byScopeSet map[string][]int
}

type scopedGlob struct {
	matcher *gitignore.GitIgnore
	negated bool
	scope   int // index into scopes, -1 when the glob can match any path
}

// globScope holds the literal leading directories of a glob, ending in "/".
type globScope struct {
	dir      string
	anchored bool
}

// globLiteralEnd lists the characters at which a glob stops being matched literally by
// go-gitignore: glob syntax, escapes, and regex metacharacters that go-gitignore passes through.
const globLiteralEnd = `*?[\+()|{}$^`

func newScopedMatcher(globs []string) *scopedMatcher {
	m := &scopedMatcher{
		globs:      make([]scopedGlob, len(globs)),
		byDir:      map[string][]int{},
		byScopeSet: map[string][]int{},
	}

	scopeIndex := map[globScope]int{}
	for i, glob := range globs {
		lines := []string{glob}
		_, negated := globPattern(glob)
		if negated {
			// "|" matches every path, unlike "*" with newlines, so the matcher is false iff the negated glob matches.
			lines = []string{"|", glob}
		}
		m.globs[i] = scopedGlob{matcher: gitignore.CompileIgnoreLines(lines...), negated: negated, scope: -1}

		scope := scopeOfGlob(glob)
		if scope.dir == "" {
			continue
		}
		index, ok := scopeIndex[scope]
		if !ok {
			index = len(m.scopes)
			scopeIndex[scope] = index
			m.scopes = append(m.scopes, scope)
		}
		m.globs[i].scope = index
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

// scopeOfGlob mirrors how go-gitignore turns a line into a regular expression. It returns an empty
// scope whenever the leading directories of the glob are not required literally.
func scopeOfGlob(glob string) globScope {
	pattern, _ := globPattern(glob)
	// go-gitignore strips one more leading "#" or "!", and compiles a leading "/**/" to an optional
	// prefix. "|", "{" and its "#$~" placeholder for "*" reach the regular expression unescaped, where
	// they can make the leading directories optional.
	if strings.HasPrefix(pattern, "#") || strings.HasPrefix(pattern, "!") || strings.HasPrefix(pattern, "/**/") ||
		strings.ContainsAny(pattern, "|{") || strings.Contains(pattern, "#$~") {
		return globScope{}
	}

	literalEnd := strings.IndexAny(pattern, globLiteralEnd)
	if literalEnd == -1 {
		literalEnd = len(pattern)
	}

	// go-gitignore compiles a "/**" that is not "/**/" to "(|/.*)", so "dir/**" also matches a file named "dir".
	if literalEnd > 0 && strings.HasPrefix(pattern[literalEnd-1:], "/**") && !strings.HasPrefix(pattern[literalEnd-1:], "/**/") {
		literalEnd--
	}

	dir := pattern[:strings.LastIndex(pattern[:literalEnd], "/")+1]
	return globScope{dir: dir, anchored: strings.HasPrefix(dir, "/")}
}

// appliesTo reports whether a path in dir, which ends in "/" or is empty, can match a glob with this scope.
func (s globScope) appliesTo(dir string) bool {
	if s.anchored {
		// go-gitignore compiles a leading "/" to "^(|/)", so the pattern also matches without it.
		return strings.HasPrefix(dir, s.dir) || strings.HasPrefix(dir, s.dir[1:])
	}
	return strings.HasPrefix(dir, s.dir) || strings.Contains(dir, "/"+s.dir)
}

func (m *scopedMatcher) MatchesPath(path string) bool {
	slashPath := filepath.ToSlash(path)
	applicable := m.globsFor(slashPath[:strings.LastIndex(slashPath, "/")+1])
	// go-gitignore's result is decided by the last glob that matches the path.
	for i := len(applicable) - 1; i >= 0; i-- {
		if glob := m.globs[applicable[i]]; glob.matcher.MatchesPath(slashPath) != glob.negated {
			return !glob.negated
		}
	}
	return false
}

func (m *scopedMatcher) globsFor(dir string) []int {
	m.mu.RLock()
	applicable, ok := m.byDir[dir]
	m.mu.RUnlock()
	if ok {
		return applicable
	}

	inScope := make([]bool, len(m.scopes))
	var key strings.Builder
	for i, scope := range m.scopes {
		if scope.appliesTo(dir) {
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
			if glob.scope < 0 || inScope[glob.scope] {
				applicable = append(applicable, i)
			}
		}
		m.byScopeSet[key.String()] = applicable
	}
	m.byDir[dir] = applicable
	return applicable
}
