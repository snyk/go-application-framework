package utils

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	gitignore "github.com/sabhiram/go-gitignore"
)

// scopedMatcher gives the same result as gitignore.CompileIgnoreLines(globs...).MatchesPath, but
// evaluates each path only against the globs that can match it.
//
// Every glob built from an ignore file starts with that file's directory, and go-gitignore can only
// match a pattern where its literal leading directories appear in the path: at the start when the
// pattern starts with "/", or at the start or after any "/" otherwise. In a tree with many nested
// ignore files, most globs therefore cannot match a given path. Paths that share a directory share
// the same applicable globs, so each distinct set is compiled once.
type scopedMatcher struct {
	globs  []string
	scopes []globScope
	unique []globScope

	mu         sync.Mutex
	byDir      map[string]*gitignore.GitIgnore
	byScopeSet map[string]*gitignore.GitIgnore
}

// globScope holds the literal leading directories of a glob, ending in "/". An empty dir means
// the glob can match any path.
type globScope struct {
	dir      string
	anchored bool
}

// globLiteralEnd lists the characters at which a glob stops being matched literally by
// go-gitignore: glob syntax, escapes, and regex metacharacters that go-gitignore passes through.
const globLiteralEnd = `*?[\+()|{}$^`

func newScopedMatcher(globs []string) *scopedMatcher {
	m := &scopedMatcher{
		globs:      globs,
		scopes:     make([]globScope, len(globs)),
		byDir:      map[string]*gitignore.GitIgnore{},
		byScopeSet: map[string]*gitignore.GitIgnore{},
	}

	seen := map[globScope]bool{}
	for i, glob := range globs {
		scope := scopeOfGlob(glob)
		m.scopes[i] = scope
		if scope.dir != "" && !seen[scope] {
			seen[scope] = true
			m.unique = append(m.unique, scope)
		}
	}

	return m
}

func scopeOfGlob(glob string) globScope {
	pattern := strings.TrimRight(glob, "\r")
	if strings.HasPrefix(pattern, "#") {
		return globScope{}
	}

	pattern = strings.TrimPrefix(strings.Trim(pattern, " "), "!")
	if strings.HasPrefix(pattern, "#") || strings.HasPrefix(pattern, "!") || strings.HasPrefix(pattern, "/**/") {
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
	if dir == "/" {
		return globScope{}
	}

	return globScope{dir: dir, anchored: strings.HasPrefix(dir, "/")}
}

// contains reports whether a path in dir, which ends in "/" or is empty, can match a glob with this scope.
func (s globScope) contains(dir string) bool {
	if s.dir == "" || strings.HasPrefix(dir, s.dir) {
		return true
	}

	if s.anchored {
		return strings.HasPrefix(dir, s.dir[1:])
	}

	return strings.Contains(dir, "/"+s.dir)
}

func (m *scopedMatcher) MatchesPath(path string) bool {
	slashPath := filepath.ToSlash(path)
	return m.matcherFor(slashPath[:strings.LastIndex(slashPath, "/")+1]).MatchesPath(path)
}

func (m *scopedMatcher) matcherFor(dir string) *gitignore.GitIgnore {
	m.mu.Lock()
	defer m.mu.Unlock()

	if matcher, ok := m.byDir[dir]; ok {
		return matcher
	}

	inScope := map[globScope]bool{}
	var key strings.Builder
	for i, scope := range m.unique {
		if scope.contains(dir) {
			inScope[scope] = true
			key.WriteString(strconv.Itoa(i))
			key.WriteByte(',')
		}
	}

	matcher, ok := m.byScopeSet[key.String()]
	if !ok {
		applicable := make([]string, 0, len(m.globs))
		for i, glob := range m.globs {
			if m.scopes[i].dir == "" || inScope[m.scopes[i]] {
				applicable = append(applicable, glob)
			}
		}
		matcher = gitignore.CompileIgnoreLines(applicable...)
		m.byScopeSet[key.String()] = matcher
	}

	m.byDir[dir] = matcher
	return matcher
}
