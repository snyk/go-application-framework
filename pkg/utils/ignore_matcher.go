package utils

import (
	"os"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
)

// ignoreMatcher is a drop-in replacement for go-gitignore's GitIgnore.MatchesPath that returns
// identical results, but avoids testing every pattern against every path.
//
// go-gitignore compiles each rule into an anchored regular expression of the form
// "^(|/)<rest>" (rule starts with "/") or "^(|.*/)<rest>" (anything else) and evaluates all of
// them, in order, for every path. GAF prefixes every rule with the absolute directory of the ignore
// file it came from, so in a repository with many nested ignore files almost all patterns can
// never match a given path, yet all of them are evaluated.
//
// Any match of <rest> must begin with regexp.LiteralPrefix(<rest>). Truncating that literal to its
// last "/" yields a directory key that must appear in the path at a "/" boundary: at the start
// (or after a leading "/") for "^(|/)" patterns, or after any "/" for "^(|.*/)" patterns.
// Patterns are bucketed by that key, so a path only evaluates the patterns whose key is one of its
// own directory prefixes. Patterns without a usable key are always evaluated. Candidates are
// evaluated in their original order, so last-match-wins and negation semantics are unchanged.
//
// In addition, every literal at the top level of a pattern must occur in any path the pattern
// matches, so a cheap substring check rules out most regular expression evaluations.
type ignoreMatcher struct {
	patterns []ignorePattern
	always   []int            // patterns that must be evaluated for every path
	anchored map[string][]int // "^(|/)" patterns keyed by the directory their match must start with
	floating map[string][]int // "^(|.*/)" patterns keyed by a directory that must follow a "/"
}

type ignorePattern struct {
	re       func() *regexp.Regexp // compiled on first use; nil if the expression is invalid
	negate   bool
	required []string // literals that any matching path contains
}

var ignoreMatcherCandidatePool = sync.Pool{New: func() any {
	s := make([]int, 0, 256)
	return &s
}}

const (
	anchoredPatternPrefix = "^(|/)"
	floatingPatternPrefix = "^(|.*/)"
)

func compileIgnoreMatcher(lines ...string) *ignoreMatcher {
	m := &ignoreMatcher{anchored: map[string][]int{}, floating: map[string][]int{}}
	for _, line := range lines {
		expr, negate, ok := ignoreLineToRegexp(line)
		if !ok {
			continue
		}
		// Compiling is deferred until a path passes the index and literal checks; most patterns
		// of a large repository are never evaluated. go-gitignore drops patterns that fail to
		// compile, an invalid pattern here never matches, which is equivalent.
		re := sync.OnceValue(func() *regexp.Regexp {
			compiled, err := regexp.Compile(expr)
			if err != nil {
				return nil
			}
			return compiled
		})
		idx := len(m.patterns)
		m.patterns = append(m.patterns, ignorePattern{re: re, negate: negate, required: requiredLiterals(expr)})
		m.index(idx, expr)
	}
	return m
}

func (m *ignoreMatcher) index(idx int, expr string) {
	bucket := m.floating
	rest, found := strings.CutPrefix(expr, floatingPatternPrefix)
	if !found {
		bucket = m.anchored
		rest, found = strings.CutPrefix(expr, anchoredPatternPrefix)
	}
	key := ""
	if found {
		if restRe, err := regexp.Compile(rest); err == nil {
			literal, _ := restRe.LiteralPrefix()
			if i := strings.LastIndexByte(literal, '/'); i >= 0 {
				key = literal[:i+1]
			}
		}
	}
	if key == "" {
		m.always = append(m.always, idx)
		return
	}
	bucket[key] = append(bucket[key], idx)
}

// MatchesPath reports whether path is ignored; same contract as go-gitignore's MatchesPath.
func (m *ignoreMatcher) MatchesPath(path string) bool {
	path = strings.ReplaceAll(path, string(os.PathSeparator), "/")

	pooled, ok := ignoreMatcherCandidatePool.Get().(*[]int)
	if !ok {
		pooled = &[]int{}
	}
	defer func() { ignoreMatcherCandidatePool.Put(pooled) }()
	candidates := append((*pooled)[:0], m.always...)

	if len(m.anchored) > 0 {
		candidates = m.appendDirPrefixes(candidates, m.anchored, path)
		if strings.HasPrefix(path, "/") {
			candidates = m.appendDirPrefixes(candidates, m.anchored, path[1:])
		}
	}
	if len(m.floating) > 0 {
		// the key may start at the beginning of the path or right after any "/"
		for start := 0; start < len(path); {
			candidates = m.appendDirPrefixes(candidates, m.floating, path[start:])
			next := strings.IndexByte(path[start:], '/')
			if next < 0 {
				break
			}
			start += next + 1
		}
	}

	slices.Sort(candidates)
	candidates = slices.Compact(candidates)
	*pooled = candidates

	matched := false
	for _, idx := range candidates {
		p := &m.patterns[idx]
		if p.matches(path) {
			if !p.negate {
				matched = true
			} else if matched {
				matched = false
			}
		}
	}
	return matched
}

func (p *ignorePattern) matches(path string) bool {
	for _, literal := range p.required {
		if !strings.Contains(path, literal) {
			return false
		}
	}
	re := p.re()
	return re != nil && re.MatchString(path)
}

// requiredLiterals returns the literals in the top-level concatenation of expr; all of them are
// part of every match.
func requiredLiterals(expr string) []string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil || re.Op != syntax.OpConcat {
		return nil
	}
	var literals []string
	for _, sub := range re.Sub {
		if sub.Op == syntax.OpLiteral && sub.Flags&syntax.FoldCase == 0 {
			literals = append(literals, string(sub.Rune))
		}
	}
	// check the most selective (longest) literal first
	slices.SortStableFunc(literals, func(a, b string) int { return len(b) - len(a) })
	return literals
}

// appendDirPrefixes appends the patterns of every key in bucket that equals one of the
// "/"-terminated prefixes of s.
func (m *ignoreMatcher) appendDirPrefixes(candidates []int, bucket map[string][]int, s string) []int {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			if idxs, ok := bucket[s[:i+1]]; ok {
				candidates = append(candidates, idxs...)
			}
		}
	}
	return candidates
}

var (
	ignoreLineHashOrBang      = regexp.MustCompile(`^(\#|\!)`)
	ignoreLineNeedsLeadSlash  = regexp.MustCompile(`([^\/+])/.*\*\.`)
	ignoreLineDot             = regexp.MustCompile(`\.`)
	ignoreLineSlashStarSlash  = regexp.MustCompile(`/\*\*/`)
	ignoreLineStarStarSlash   = regexp.MustCompile(`\*\*/`)
	ignoreLineSlashStarStar   = regexp.MustCompile(`/\*\*`)
	ignoreLineEscapedStar     = regexp.MustCompile(`\\\*`)
	ignoreLineStar            = regexp.MustCompile(`\*`)
	ignoreLineMagicStarString = "#$~"
)

// ignoreLineToRegexp is a verbatim port of getPatternFromLine from
// github.com/sabhiram/go-gitignore (MIT License, Copyright (c) 2015 Shaba Abhiram), which this
// matcher must stay bit-for-bit compatible with. It returns the regular expression source instead
// of a compiled expression so that the expression can be indexed.
func ignoreLineToRegexp(line string) (expr string, negate bool, ok bool) {
	line = strings.TrimRight(line, "\r")
	if strings.HasPrefix(line, `#`) {
		return "", false, false
	}
	line = strings.Trim(line, " ")
	if line == "" {
		return "", false, false
	}
	if line[0] == '!' {
		negate = true
		line = line[1:]
	}
	if ignoreLineHashOrBang.MatchString(line) {
		line = line[1:]
	}
	if ignoreLineNeedsLeadSlash.MatchString(line) && line[0] != '/' {
		line = "/" + line
	}
	line = ignoreLineDot.ReplaceAllString(line, `\.`)
	if strings.HasPrefix(line, "/**/") {
		line = line[1:]
	}
	line = ignoreLineSlashStarSlash.ReplaceAllString(line, `(/|/.+/)`)
	line = ignoreLineStarStarSlash.ReplaceAllString(line, `(|.`+ignoreLineMagicStarString+`/)`)
	line = ignoreLineSlashStarStar.ReplaceAllString(line, `(|/.`+ignoreLineMagicStarString+`)`)
	line = ignoreLineEscapedStar.ReplaceAllString(line, `\`+ignoreLineMagicStarString)
	line = ignoreLineStar.ReplaceAllString(line, `([^/]*)`)
	line = strings.ReplaceAll(line, "?", `\?`)
	line = strings.ReplaceAll(line, ignoreLineMagicStarString, "*")

	if strings.HasSuffix(line, "/") {
		expr = line + "(|.*)$"
	} else {
		expr = line + "(|/.*)$"
	}
	if strings.HasPrefix(expr, "/") {
		expr = anchoredPatternPrefix + expr[1:]
	} else {
		expr = floatingPatternPrefix + expr
	}
	return expr, negate, true
}
