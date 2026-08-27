/*
 * © 2023 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os/user"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

const MAX_WRITE_RETRIES = 10
const SANITIZE_REPLACEMENT_STRING string = "***"

// SENSITIVE_FIELD_NAMES is a list of field names that should be sanitized.
var SENSITIVE_FIELD_NAMES = []string{
	"headers",
	"user",
	"passw",
	"token",
	"key",
	"secret",
}

type ScrubbingLogWriter interface {
	// AddTerm takes a regex pattern to scrub
	AddTerm(term string, matchGroup int)
	// AddTermsToReplace takes exact strings to scrub
	AddTermsToReplace(args []string)
	RemoveTerm(term string)
}

type scrubStruct struct {
	// the group to redact from the regex pattern if `regex` is populated, otherwise 0
	groupToRedact int
	// the regex pattern to scrub
	regex *regexp.Regexp
	// the exact term to replace
	replace string
}

type ScrubbingDict map[string]scrubStruct

type scrubbingLevelWriter struct {
	m         sync.RWMutex
	writer    zerolog.LevelWriter
	scrubDict ScrubbingDict
}

type scrubbingIoWriter struct {
	m         sync.RWMutex
	writer    io.Writer
	scrubDict ScrubbingDict
}

func NewScrubbingWriter(writer zerolog.LevelWriter, scrubDict ScrubbingDict) zerolog.LevelWriter {
	dict := addMandatoryMasking(scrubDict)
	levelWriter := scrubbingLevelWriter{
		writer:    writer,
		scrubDict: dict,
	}
	return &levelWriter
}

func NewScrubbingIoWriter(writer io.Writer, scrubDict ScrubbingDict) io.Writer {
	dict := addMandatoryMasking(scrubDict)
	return &scrubbingIoWriter{
		writer:    writer,
		scrubDict: dict,
	}
}

func (w *scrubbingIoWriter) AddTermsToReplace(terms []string) {
	w.m.Lock()
	defer w.m.Unlock()
	for _, v := range terms {
		addStaticTermToDict(v, w.scrubDict)
	}
}

func (w *scrubbingIoWriter) AddTerm(term string, matchGroup int) {
	// lock for dict readers and writers
	w.m.Lock()
	defer w.m.Unlock()
	addRegexTermToDict(term, matchGroup, w.scrubDict)
}

func addStaticTermToDict(replaceTerm string, dict ScrubbingDict) {
	if replaceTerm != "" {
		dict[replaceTerm] = scrubStruct{0, nil, replaceTerm}
	}
}

func addRegexTermToDict(regexTerm string, matchGroup int, dict ScrubbingDict) {
	if regexTerm != "" {
		dict[regexTerm] = scrubStruct{matchGroup, regexp.MustCompile(regexTerm), ""}
	}
}

func (w *scrubbingIoWriter) RemoveTerm(term string) {
	// lock for dict readers and writers
	w.m.Lock()
	defer w.m.Unlock()
	delete(w.scrubDict, term)
}

// REDACTION_TERMS ([]string) arbitrary literal terms to redact from analytics/log
// output, in addition to the token/OAuth-derived terms GetScrubDictFromConfig
// already adds. Lives here rather than pkg/configuration since this package is
// its only reader, matching the precedent of local_workflows.ConfigurationNewAuthenticationToken.
const REDACTION_TERMS string = "internal_redaction_terms"

func GetScrubDictFromConfig(config configuration.Configuration) ScrubbingDict {
	dict := getDefaultDict()
	addStaticTermToDict(config.GetString(configuration.AUTHENTICATION_TOKEN), dict)
	addStaticTermToDict(config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN), dict)
	addStaticTermToDict(config.GetString(auth.PARAMETER_CLIENT_SECRET), dict)
	addStaticTermToDict(config.GetString(auth.PARAMETER_CLIENT_ID), dict)
	for _, term := range config.GetStringSlice(REDACTION_TERMS) {
		addStaticTermToDict(term, dict)
	}
	token, err := auth.GetOAuthToken(config)
	if err != nil || token == nil {
		return dict
	}
	addStaticTermToDict(token.AccessToken, dict)
	addStaticTermToDict(token.RefreshToken, dict)
	return dict
}

func getDefaultDict() ScrubbingDict {
	dict := ScrubbingDict{}
	addMandatoryMasking(dict)
	return dict
}

func (w *scrubbingLevelWriter) AddTermsToReplace(terms []string) {
	w.m.Lock()
	defer w.m.Unlock()
	for _, v := range terms {
		addStaticTermToDict(v, w.scrubDict)
	}
}

func (w *scrubbingLevelWriter) AddTerm(term string, matchGroup int) {
	// lock for dict readers and writers
	w.m.Lock()
	defer w.m.Unlock()
	addRegexTermToDict(term, matchGroup, w.scrubDict)
}

func (w *scrubbingLevelWriter) RemoveTerm(term string) {
	// lock for dict readers and writers
	w.m.Lock()
	defer w.m.Unlock()
	delete(w.scrubDict, term)
}

func (w *scrubbingLevelWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	// lock for dict changes, but allow unlimited readers
	w.m.RLock()
	defer w.m.RUnlock()
	return internalWrite(w.scrubDict, p, func(p []byte) (int, error) {
		return w.writer.WriteLevel(level, p)
	})
}

func addMandatoryMasking(dict ScrubbingDict) ScrubbingDict {
	const charGroup = "[a-zA-Z0-9-_:.=/+~]{6,}"
	s := `(http(s)?://)((.+?):(.+?))@(\S+)`
	dict[s] = scrubStruct{
		groupToRedact: 3,
		regex:         regexp.MustCompile(s),
	}

	s = fmt.Sprintf(`([t|T]oken )(%s)`, charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	s = fmt.Sprintf(`([b|B]earer )(%s)`, charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	s = fmt.Sprintf(`([b|B]asic )(%s)`, charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	s = fmt.Sprintf("([n|N]egotiate )(%s)", charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	s = fmt.Sprintf("(gh[ps])_(%s)", charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	s = fmt.Sprintf("(github_pat_)(%s)", charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	// Snyk PATs
	s = auth.PAT_REGEX
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	// github
	s = fmt.Sprintf(`(access_token[\\="\s:]+)(%s)&?`, charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	s = fmt.Sprintf(`(refresh_token[\\="\s:]+)(%s)&?`, charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	s = fmt.Sprintf(`(token[\\="\s:]+)(%s)&?`, charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	s = fmt.Sprintf(`(SNYK_TOKEN)=(%s)`, charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	// Hide whatever is the current username
	u, err := user.Current()
	if err == nil {
		s = fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(u.Username))
		addRegexTermToDict(s, 0, dict)
	}

	// The legacy CLI's snyk-config package prints the entire configuration in debug mode.
	// It begins with some pseudo-JSON structure, which we can redact.
	// The capture must not be a plain greedy `.*`: that runs to the *last* `]` in the whole
	// buffer and swallows any structure that follows the dump (see CLI-1732). Instead the
	// capture may cross a balanced `[...]` pair (the dump nests one), but never an unpaired
	// closing bracket, so it always stops at the dump's own `]`. The final `\[` alternative
	// keeps a stray, unbalanced `[` inside the dump from failing the match altogether.
	// Quoted spans are consumed whole, before the bracket-tracking alternatives get a look —
	// otherwise a `]` or `[` inside a quoted value (e.g. `'a]b'`) reads as real bracket nesting
	// and the capture closes early, right at that inner bracket. `\\.` keeps a backslash-escaped
	// bounding quote (e.g. `'a\'b]c'`) part of the same span instead of ending it prematurely.
	s = `_:\s*\[(?<everything_inside_hard_brackets>(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\[[^\]]*\]|[^\[\]]|\[)*)\]`
	dict[s] = scrubStruct{
		groupToRedact: 1,
		regex:         regexp.MustCompile(s),
	}

	// JSON-formatted data, in general
	kws := strings.Join(SENSITIVE_FIELD_NAMES, "|")
	s = fmt.Sprintf(`(?i)"[^"]*(?<json_key>%s)[^"]*"\s*:\s*"(?<json_value>[^"]*)"`, kws)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	// Same as above, only with short form
	shorts := []string{"p", "u"}
	shortForm := strings.Join(shorts, "")
	s = fmt.Sprintf(`(?im)'[%s]=(?<value>[^'\n]*)'`, shortForm)
	dict[s] = scrubStruct{
		groupToRedact: 1,
		regex:         regexp.MustCompile(s),
	}

	// Specific short-form scrubbing of the JSON-ish log structures
	// Appear in the snyk-config debug logging as various constellations of { 'u': 'john.doe', } with or without quotes,
	// and values can contain spaces, double and/or single quotes.
	//
	// Single- and double-quoted values get their own pattern so each value can be bounded by
	// its own quote character. A single pattern bounded by `['"]` needs a greedy `.*` to allow
	// the opposite quote inside the value, and that greedy run reaches the *last* quote on the
	// line, swallowing every field that follows it (see CLI-1732). `\n` stays excluded so the
	// bounded classes keep the line-at-a-time reach the previous `.` had. An escaped instance of
	// the bounding quote (e.g. `Nick\'s`) is kept part of the value via `\\.`, the same idiom the
	// CLI-argument pattern below uses — without it, the class stops at that escaped quote instead
	// of the value's real closing one and leaks the remainder of the value.
	for _, quote := range []string{`'`, `"`} {
		s = fmt.Sprintf(`(?i)(?<short_form_key>\b[%s]\b)[,'":]+\s*%s(?<short_form_value>(?:[^%s\n\\]|\\.)*)%s[,}]?`, shortForm, quote, quote, quote)
		dict[s] = scrubStruct{
			groupToRedact: 2,
			regex:         regexp.MustCompile(s),
		}
	}

	// Same as above, but for values with no surrounding quotes at all, e.g. u: john.doe,
	// The value class excludes ':' too: without that, a greedy separator backtracking off an
	// already-redacted 'key': '***' leaves the colon for this group to swallow instead.
	s = fmt.Sprintf(`(?i)(?<short_form_key>\b[%s]\b)[,'":]+\s*(?<short_form_value>[^,'":\s]+)[,}]?`, shortForm)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	// CLI argument-style-specific scrubbing
	// Many cases are already covered by the JSON scrubbing above, thus this might seem incomplete.
	// Refer to the unit tests for the full set of covered cases.
	// An unescaped `"` ends the value: when the argument list is logged inside a JSON string that
	// quote closes the string, and a plain `\S*` would run on through the rest of the event and
	// redact every field after it (see CLI-1732). An *escaped* quote is still part of the value,
	// so `\\.` keeps `-p hun\"ter2` (and Windows paths such as `-p C:\dir\file`) fully redacted.
	s = fmt.Sprintf(`(?im)\-[%s][\s=](?<short_form_value>(?:[^\s"\\]|\\.)*)`, shortForm)
	dict[s] = scrubStruct{
		groupToRedact: 1,
		regex:         regexp.MustCompile(s),
	}

	return dict
}

func (w *scrubbingLevelWriter) Write(p []byte) (int, error) {
	// lock for dict changes, but allow unlimited readers
	w.m.RLock()
	defer w.m.RUnlock()
	return internalWrite(w.scrubDict, p, w.writer.Write)
}

// Scrub applies scrubDict's redaction rules to data, treated as a JSON-structured log line.
// Use ScrubValue for a bare, non-JSON leaf value.
func Scrub(data []byte, scrubDict ScrubbingDict) []byte {
	return scrub(data, scrubDict, true)
}

// ScrubValue applies scrubDict's redaction rules to a value that is not itself JSON-structured,
// e.g. a leaf string that a later json.Marshal will quote. Skips Scrub's JSON-value quoting and
// digit-fusion protections, which would otherwise stray-quote or under-redact plain text.
func ScrubValue(data []byte, scrubDict ScrubbingDict) []byte {
	return scrub(data, scrubDict, false)
}

func scrub(p []byte, scrubDict ScrubbingDict, jsonAware bool) []byte {
	s := string(p)
	// The dictionary order is important here, as we want potentially overlapping regexes to be applied
	// in a specific order every time. Since dictionaries are unordered, we sort the keys here.
	keys := make([]string, 0, len(scrubDict))
	for k := range scrubDict {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := scrubDict[key]
		// scrub from the replacement list first
		if entry.replace != "" {
			if jsonAware {
				s = RedactStaticTerm(s, entry.replace, SANITIZE_REPLACEMENT_STRING)
			} else {
				s = strings.ReplaceAll(s, entry.replace, SANITIZE_REPLACEMENT_STRING)
			}
			continue
		}
		// then scrub from the regex list
		s = redactMatchedGroup(s, entry.regex, entry.groupToRedact)
	}
	return []byte(s)
}

// RedactStaticTerm replaces every occurrence of term in s with replacement, quoting the
// replacement when term sits in a bare (unquoted) JSON value position, and leaving an occurrence
// untouched when it's only a digit-fused slice of a larger bare number.
//
// term has no regex capture to bound it, so only the characters immediately around each match are
// checked. A term preceded by `:`, `,` or `[` and followed by `,`, `}` or `]` is a bare value
// (number/bool/null); an unquoted replacement there is invalid JSON (see CLI-1732), so the
// replacement gets quoted instead. A term at the very start or end of s, with no boundary
// character on that side, is left bare rather than guessed at. A term already inside a quoted
// string is also left bare, and never treated as digit-fused.
//
// A numeric term can also land mid-number in a bare position (e.g. redacting "1000" out of an
// unrelated "durationMs":10001234) — there it's a slice of a larger number token, and no amount of
// quoting keeps that valid, so the occurrence is left alone rather than corrupting the number.
//
// Exported for reuse by pkg/analytics's SanitizeStaticValues, which has the same corruption risk.
func RedactStaticTerm(s, term, replacement string) string {
	if term == "" {
		return s
	}
	var builder strings.Builder
	builder.Grow(len(s))
	end := 0
	var qs quoteState
	for {
		idx := strings.Index(s[end:], term)
		if idx < 0 {
			break
		}
		start := end + idx
		matchEnd := start + len(term)
		qs = qs.advance(s[end:start])
		quoted := qs.inQuotes
		builder.WriteString(s[end:start])
		switch {
		case !quoted && isFusedToAdjacentNumberChar(s, start, matchEnd):
			builder.WriteString(s[start:matchEnd])
		case !quoted && isBareJSONValueSpan(s, start, matchEnd):
			builder.WriteByte('"')
			builder.WriteString(replacement)
			builder.WriteByte('"')
		default:
			builder.WriteString(replacement)
		}
		qs = qs.advance(s[start:matchEnd])
		end = matchEnd
	}
	builder.WriteString(s[end:])
	return builder.String()
}

// quoteState tracks whether a scan position sits inside an open, unescaped double-quoted JSON
// string, plus whether the most recently scanned span ended on an unresolved backslash. That
// second field matters because RedactStaticTerm scans in separate pieces (the text before a match,
// then the match itself) rather than the whole string in one pass: without it, a backslash landing
// as the very last byte of one piece would have its escaped character re-examined as fresh, unescaped
// input by the next piece, flipping inQuotes on a quote that was actually just escaped.
type quoteState struct {
	inQuotes bool
	escaping bool
}

// advance scans span and returns the state after it, given qs was the state before span.
func (qs quoteState) advance(span string) quoteState {
	for i := 0; i < len(span); i++ {
		if qs.escaping {
			qs.escaping = false
			continue
		}
		switch span[i] {
		case '\\':
			qs.escaping = true
		case '"':
			qs.inQuotes = !qs.inQuotes
		}
	}
	return qs
}

// isBareJSONValueSpan reports whether s[start:end] is an unquoted JSON value: preceded by `:`,
// `,` or `[` and followed by `,`, `}` or `]`, with both neighbors required (skipping over any
// insignificant JSON whitespace — space, tab, CR, LF — in between, so pretty-printed JSON like
// `: 12345,` is recognized the same as compact `:12345,`). This only risks misreading ordinary
// prose as a bare value when that prose sits outside any JSON string and next to a real `:`/`,` —
// callers that gate jsonAware on the input actually being valid JSON (see internalWrite) rule that
// out, since prose inside valid JSON is always inside a quoted string, where the `quoted` check in
// RedactStaticTerm's caller already skips this function entirely.
func isBareJSONValueSpan(s string, start, end int) bool {
	i := start - 1
	for i >= 0 && isJSONWhitespace(s[i]) {
		i--
	}
	precededByValueStart := i >= 0 && strings.ContainsRune(":,[", rune(s[i]))

	j := end
	for j < len(s) && isJSONWhitespace(s[j]) {
		j++
	}
	followedByValueEnd := j < len(s) && strings.ContainsRune(",}]", rune(s[j]))

	return precededByValueStart && followedByValueEnd
}

func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// isFusedToAdjacentNumberChar reports whether s[start:end] touches a digit or other
// numeric-literal character (`.`, `-`, `+`, `e`, `E`) on either side — i.e. it's a slice of a
// larger unquoted number, not a complete value.
func isFusedToAdjacentNumberChar(s string, start, end int) bool {
	precededByNumberChar := start > 0 && isJSONNumberChar(s[start-1])
	followedByNumberChar := end < len(s) && isJSONNumberChar(s[end])
	return precededByNumberChar || followedByNumberChar
}

func isJSONNumberChar(b byte) bool {
	return (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '+' || b == 'e' || b == 'E'
}

// redactMatchedGroup replaces capture group groupToRedact of every match of regex in s,
// addressing each occurrence by the position the regex matched it at.
//
// Addressing by position matters: looking the captured *text* back up in s and replacing every
// occurrence of it lets a short or structural capture — a one-character value, or a value that
// happens to be `{`, `,` or `"` — blank out identical text elsewhere in the same event, which
// corrupts the surrounding payload (see CLI-1732). Matches returned by FindAll are non-overlapping
// and in order, so the spans can be stitched back together in a single pass.
func redactMatchedGroup(s string, regex *regexp.Regexp, groupToRedact int) string {
	matches := regex.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s
	}

	var builder strings.Builder
	builder.Grow(len(s))
	end := 0
	for _, match := range matches {
		lo, hi := 2*groupToRedact, 2*groupToRedact+1
		// group out of range, or it did not participate in the match, or it matched empty
		if hi >= len(match) || match[lo] < 0 || match[hi] <= match[lo] {
			continue
		}
		builder.WriteString(s[end:match[lo]])
		builder.WriteString(SANITIZE_REPLACEMENT_STRING)
		end = match[hi]
	}
	builder.WriteString(s[end:])
	return builder.String()
}

func (w *scrubbingIoWriter) Write(p []byte) (int, error) {
	// lock for dict changes, but allow unlimited readers
	w.m.RLock()
	defer w.m.RUnlock()
	return internalWrite(w.scrubDict, p, w.writer.Write)
}

// internalWrite scrubs p and writes it out via writeFunc. p is usually the compact JSON zerolog
// itself encodes, but a writer misconfigured downstream of a non-JSON formatter (e.g. a console
// writer that reformats JSON into human-readable text before it reaches here) can hand it prose
// instead — RedactStaticTerm's bare-value quoting is only correct against real JSON, so p's own
// validity, not the caller's assumption, decides which mode applies.
func internalWrite(dict ScrubbingDict, p []byte, writeFunc func(p []byte) (int, error)) (int, error) {
	scrubbedDataWritten := 0
	scrubbedData := scrub(p, dict, json.Valid(p))
	var err error
	var written int
	for errorsSeen := 0; scrubbedDataWritten < len(scrubbedData); {
		written, err = writeFunc(scrubbedData[scrubbedDataWritten:])
		scrubbedDataWritten += written

		if err != nil {
			errorsSeen++
			// exponential backoff
			time.Sleep(time.Millisecond * time.Duration(errorsSeen*errorsSeen))
		}

		// circuit breaker
		if errorsSeen > MAX_WRITE_RETRIES {
			return len(p), err
		}
	}
	if scrubbedDataWritten != len(scrubbedData) {
		return len(p), err
	}
	return len(p), nil // we return the original length, since we don't know the length of the redacted string
}
