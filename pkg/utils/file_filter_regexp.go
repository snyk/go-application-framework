package utils

import (
	"regexp"
	"strings"
)

// Ported from getPatternFromLine in github.com/sabhiram/go-gitignore
// (MIT License, Copyright (c) 2015 Shaba Abhiram), which scopedMatcher must match exactly.
var (
	globEscapedHashOrBang  = regexp.MustCompile(`^(\#|\!)`)
	globNeedsLeadingSlash  = regexp.MustCompile(`([^\/+])/.*\*\.`)
	globDot                = regexp.MustCompile(`\.`)
	globSlashStarStarSlash = regexp.MustCompile(`/\*\*/`)
	globStarStarSlash      = regexp.MustCompile(`\*\*/`)
	globSlashStarStar      = regexp.MustCompile(`/\*\*`)
	globEscapedStar        = regexp.MustCompile(`\\\*`)
	globStar               = regexp.MustCompile(`\*`)
)

// globRegexp returns the regular expression go-gitignore compiles for glob, and whether glob is
// negated. It returns "" for comments and blank globs, which go-gitignore drops.
func globRegexp(glob string) (expr string, negated bool) {
	line, negated := globPattern(glob)
	if line == "" && !negated {
		return "", false
	}
	if globEscapedHashOrBang.MatchString(line) {
		line = line[1:]
	}
	if globNeedsLeadingSlash.MatchString(line) && line[0] != '/' {
		line = "/" + line
	}
	line = globDot.ReplaceAllString(line, `\.`)

	const magicStar = "#$~"
	if strings.HasPrefix(line, "/**/") {
		line = line[1:]
	}
	line = globSlashStarStarSlash.ReplaceAllString(line, `(/|/.+/)`)
	line = globStarStarSlash.ReplaceAllString(line, `(|.`+magicStar+`/)`)
	line = globSlashStarStar.ReplaceAllString(line, `(|/.`+magicStar+`)`)
	line = globEscapedStar.ReplaceAllString(line, `\`+magicStar)
	line = globStar.ReplaceAllString(line, `([^/]*)`)
	line = strings.ReplaceAll(line, "?", `\?`)
	line = strings.ReplaceAll(line, magicStar, "*")

	if strings.HasSuffix(line, "/") {
		expr = line + "(|.*)$"
	} else {
		expr = line + "(|/.*)$"
	}
	if strings.HasPrefix(expr, "/") {
		return "^(|/)" + expr[1:], negated
	}
	return "^(|.*/)" + expr, negated
}
