package utils

import (
	"regexp"
	"strings"
)

// globRegexp and the expressions below are ported from getPatternFromLine in
// github.com/sabhiram/go-gitignore v0.0.0-20210923224102-525f6e181f06 under this license:
//
// The MIT License (MIT)
//
// Copyright (c) 2015 Shaba Abhiram
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// scopedMatcher must match go-gitignore exactly. The comparison tests in file_filter_scopes_test.go check
// this port against the go-gitignore version in go.mod.
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
