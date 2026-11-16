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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/user"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/machinecredential"
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
	// AddTermsToReplace takes exact strings to scrub, matched only as whole words
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
	// whether `replace` must stand alone as a word/identifier to match
	wholeWord bool
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
		addWholeWordTermToDict(v, w.scrubDict)
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
		dict[replaceTerm] = scrubStruct{groupToRedact: 0, replace: replaceTerm}
	}
}

// Preserve match-anywhere rules for known secrets.
func addWholeWordTermToDict(replaceTerm string, dict ScrubbingDict) {
	if replaceTerm == "" {
		return
	}
	if _, exists := dict[replaceTerm]; exists {
		return
	}
	dict[replaceTerm] = scrubStruct{groupToRedact: 0, replace: replaceTerm, wholeWord: true}
}

func addRegexTermToDict(regexTerm string, matchGroup int, dict ScrubbingDict) {
	if regexTerm != "" {
		dict[regexTerm] = scrubStruct{groupToRedact: matchGroup, regex: regexp.MustCompile(regexTerm)}
	}
}

func (w *scrubbingIoWriter) RemoveTerm(term string) {
	// lock for dict readers and writers
	w.m.Lock()
	defer w.m.Unlock()
	delete(w.scrubDict, term)
}

// REDACTION_TERMS configures literal terms redacted only as whole words.
const REDACTION_TERMS string = "internal_redaction_terms"

// minDeviceTokenTermLength mirrors machinecredential's floor for secret terms: a shorter value would
// also redact unrelated text.
const minDeviceTokenTermLength = 16

func GetScrubDictFromConfig(config configuration.Configuration) ScrubbingDict {
	dict := getDefaultDict()
	for _, secret := range secretsFromConfig(config) {
		addStaticTermToDict(secret, dict)
	}
	for _, term := range config.GetStringSlice(REDACTION_TERMS) {
		addWholeWordTermToDict(term, dict)
	}
	return dict
}

// AddSecretsFromConfig makes the writer scrub the secrets the configuration holds, wherever they appear in a
// message, and the redaction terms it configures. The writer is typically created before it is known which
// configuration a command runs on, for example the one of a profile, and this adds the secrets of that
// configuration afterwards. The secrets are scrubbed as GetScrubDictFromConfig scrubs them.
func AddSecretsFromConfig(writer ScrubbingLogWriter, config configuration.Configuration) {
	addSecretTerms(writer, secretsFromConfig(config))
	writer.AddTermsToReplace(config.GetStringSlice(REDACTION_TERMS))
}

// addSecretTerms adds literal secrets the way GetScrubDictFromConfig adds them, so both redact them alike.
func addSecretTerms(writer ScrubbingLogWriter, secrets []string) {
	var mu *sync.RWMutex
	var dict ScrubbingDict
	switch w := writer.(type) {
	case *scrubbingLevelWriter:
		mu, dict = &w.m, w.scrubDict
	case *scrubbingIoWriter:
		mu, dict = &w.m, w.scrubDict
	default:
		for _, secret := range secrets {
			writer.AddTerm(regexp.QuoteMeta(secret), 0)
		}
		return
	}
	mu.Lock()
	defer mu.Unlock()
	for _, secret := range secrets {
		addStaticTermToDict(secret, dict)
	}
}

// secretsFromConfig returns the credentials a configuration holds.
func secretsFromConfig(config configuration.Configuration) []string {
	secrets := []string{
		config.GetString(configuration.AUTHENTICATION_TOKEN),
		config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN),
		config.GetString(auth.PARAMETER_CLIENT_SECRET),
		config.GetString(auth.PARAMETER_CLIENT_ID),
	}
	if token := config.GetString(machinecredential.CONFIG_KEY_DEVICE_TOKEN); len(token) >= minDeviceTokenTermLength {
		secrets = append(secrets, token)
	}
	if fleetKey := config.GetString(machinecredential.CONFIG_KEY_FLEET_KEY); len(fleetKey) >= minDeviceTokenTermLength {
		secrets = append(secrets, fleetKey)
	}
	secrets = append(secrets, machinecredential.SecretTerms(config)...)
	if token, err := auth.GetOAuthToken(config); err == nil && token != nil {
		secrets = append(secrets, token.AccessToken, token.RefreshToken)
	}
	return slices.DeleteFunc(secrets, func(secret string) bool { return secret == "" })
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
		addWholeWordTermToDict(v, w.scrubDict)
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
	shortForm := strings.Join(shortFormFieldNames, "")
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
	// of the value's real closing one and leaks the remainder of the value. JSON string values are
	// scrubbed decoded, so an escaped quote arrives unescaped: a bounding quote followed by anything
	// other than a separator is part of the value too.
	for _, quote := range []string{`'`, `"`} {
		chars := fmt.Sprintf(`(?:[^%s\n\\]|\\.)*`, quote)
		embeddedQuote := fmt.Sprintf(`%s[^%s\s,;)\]}\\]`, quote, quote)
		s = fmt.Sprintf(`(?i)(?<short_form_key>\b[%s]\b)[,'":]+\s*%s(?<short_form_value>%s(?:%s%s)*)%s[,}]?`, shortForm, quote, chars, embeddedQuote, chars, quote)
		dict[s] = scrubStruct{
			groupToRedact: 2,
			regex:         regexp.MustCompile(s),
		}
	}

	// Same as above, but for values with no surrounding quotes at all, e.g. u: john.doe,
	// The value class excludes ':' too: without that, a greedy separator backtracking off an
	// already-redacted 'key': '***' leaves the colon for this group to swallow instead. A quote
	// inside the value belongs to it, but the first and last character are never a quote, so a
	// quoted value is left to the patterns above and a closing quote is kept.
	s = fmt.Sprintf(`(?i)(?<short_form_key>\b[%s]\b)[,'":]+\s*(?<short_form_value>[^,'":\s](?:[^,:\s]*[^,'":\s])?)[,}]?`, shortForm)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	// CLI argument-style-specific scrubbing
	// Many cases are already covered by the JSON scrubbing above, thus this might seem incomplete.
	// Refer to the unit tests for the full set of covered cases.
	// A quote is part of the value: JSON string values are scrubbed decoded, so an escaped quote in
	// the event arrives here as a bare `"`. `\\.` keeps Windows paths such as `-p C:\dir\file`
	// fully redacted.
	s = fmt.Sprintf(`(?im)\-[%s][\s=](?<short_form_value>(?:[^\s\\]|\\.)*)`, shortForm)
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

// Scrub applies scrubDict's redaction rules to data. JSON-value quoting and digit-fusion
// protection apply only when data is itself valid JSON; the caller's intent doesn't override
// what data actually is (see internalWrite). Use ScrubValue for a value already known to be a
// bare, non-JSON leaf.
func Scrub(data []byte, scrubDict ScrubbingDict) []byte {
	return scrub(data, scrubDict, json.Valid(data))
}

// ScrubValue applies scrubDict's redaction rules to a value that is not itself JSON-structured,
// e.g. a leaf string that a later json.Marshal will quote. Skips Scrub's JSON-value quoting and
// digit-fusion protections, which would otherwise stray-quote or under-redact plain text.
func ScrubValue(data []byte, scrubDict ScrubbingDict) []byte {
	return scrub(data, scrubDict, false)
}

// scrub redacts p. When jsonAware is set and p is valid JSON, each field name and value is
// scrubbed on its own (see scrubJSON); otherwise p is scrubbed as plain text.
func scrub(p []byte, scrubDict ScrubbingDict, jsonAware bool) []byte {
	rules := orderedRules(scrubDict)
	if jsonAware {
		if scrubbed, err := scrubJSON(p, rules); err == nil {
			return scrubbed
		}
	}
	return []byte(applyRules(string(p), rules, true))
}

// orderedRules puts secrets first, then longer whole-word terms, to avoid partial redaction.
func orderedRules(scrubDict ScrubbingDict) []scrubStruct {
	keys := make([]string, 0, len(scrubDict))
	for k := range scrubDict {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		wi, wj := scrubDict[keys[i]].wholeWord, scrubDict[keys[j]].wholeWord
		if wi != wj {
			return wj
		}
		if wi && len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	rules := make([]scrubStruct, len(keys))
	for i, key := range keys {
		rules[i] = scrubDict[key]
	}
	return rules
}

// applyRules redacts s as plain text. Whole-word terms are guesses rather than known secrets, so
// they are skipped when includeWholeWordTerms is false.
func applyRules(s string, rules []scrubStruct, includeWholeWordTerms bool) string {
	for _, entry := range rules {
		switch {
		case entry.replace == "":
			s = redactMatchedGroup(s, entry.regex, entry.groupToRedact)
		case !entry.wholeWord:
			s = strings.ReplaceAll(s, entry.replace, SANITIZE_REPLACEMENT_STRING)
		case includeWholeWordTerms:
			s = redactWholeWord(s, entry.replace, SANITIZE_REPLACEMENT_STRING)
		}
	}
	return s
}

// shortFormFieldNames are single-letter field names used for credentials, e.g. 'p' for password.
var shortFormFieldNames = []string{"p", "u"}

// isSensitiveFieldName reports whether the value of a field with this name is redacted as a whole.
// It matches SENSITIVE_FIELD_NAMES as case-insensitive substrings, and shortFormFieldNames exactly.
func isSensitiveFieldName(name string) bool {
	lower := strings.ToLower(name)
	for _, sensitive := range SENSITIVE_FIELD_NAMES {
		if strings.Contains(lower, sensitive) {
			return true
		}
	}
	return slices.Contains(shortFormFieldNames, lower)
}

type jsonFrame struct {
	isObject  bool
	expectKey bool
}

type jsonScrubber struct {
	p       []byte
	rules   []scrubStruct
	decoder *json.Decoder
	out     []byte
	copied  int
	end     int
	stack   []jsonFrame
}

// scrubJSON walks a valid JSON document and rewrites only the spans that change, so the output is
// valid JSON and every unchanged byte is kept as it was. Rules see one decoded field name or value
// at a time, so no pattern can run from one field into the next. Field names are not matched
// against whole-word terms. A field with a sensitive name has its whole value replaced, whatever
// its type. A changed number becomes a string. true, false and null carry no secret and are kept.
func scrubJSON(p []byte, rules []scrubStruct) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(p))
	decoder.UseNumber()
	w := &jsonScrubber{p: p, rules: rules, decoder: decoder, out: make([]byte, 0, len(p))}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return append(w.out, p[w.copied:]...), nil
		}
		if err != nil {
			return nil, err
		}
		start := skipJSONSeparators(p, w.end)
		w.end = int(decoder.InputOffset())
		if err = w.scrubToken(token, start); err != nil {
			return nil, err
		}
	}
}

func (w *jsonScrubber) scrubToken(token json.Token, start int) error {
	switch t := token.(type) {
	case json.Delim:
		if t == '{' || t == '[' {
			w.markValue()
			w.stack = append(w.stack, jsonFrame{isObject: t == '{', expectKey: true})
		} else {
			w.stack = w.stack[:len(w.stack)-1]
		}
		return nil
	case string:
		if n := len(w.stack); n > 0 && w.stack[n-1].isObject && w.stack[n-1].expectKey {
			w.stack[n-1].expectKey = false
			return w.scrubField(t, start)
		}
		w.markValue()
		return w.replaceIfChanged(start, t, applyRules(t, w.rules, true))
	case json.Number:
		w.markValue()
		return w.replaceIfChanged(start, t.String(), applyRules(t.String(), w.rules, true))
	default:
		w.markValue()
		return nil
	}
}

func (w *jsonScrubber) scrubField(name string, start int) error {
	if err := w.replaceIfChanged(start, name, applyRules(name, w.rules, false)); err != nil {
		return err
	}
	if !isSensitiveFieldName(name) {
		return nil
	}
	valueStart := skipJSONSeparators(w.p, w.end)
	var value json.RawMessage
	if err := w.decoder.Decode(&value); err != nil {
		return err
	}
	w.end = int(w.decoder.InputOffset())
	w.markValue()
	return w.replace(valueStart, SANITIZE_REPLACEMENT_STRING)
}

func (w *jsonScrubber) markValue() {
	if n := len(w.stack); n > 0 && w.stack[n-1].isObject {
		w.stack[n-1].expectKey = true
	}
}

func (w *jsonScrubber) replaceIfChanged(start int, original, scrubbed string) error {
	if scrubbed == original {
		return nil
	}
	return w.replace(start, scrubbed)
}

// replace rewrites the bytes from start to the end of the last consumed token as the JSON string s.
func (w *jsonScrubber) replace(start int, s string) error {
	encoded, err := encodeJSONString(s)
	if err != nil {
		return err
	}
	w.out = append(w.out, w.p[w.copied:start]...)
	w.out = append(w.out, encoded...)
	w.copied = w.end
	return nil
}

// skipJSONSeparators returns the offset of the first byte at or after from that starts a token.
func skipJSONSeparators(p []byte, from int) int {
	for from < len(p) && (isJSONWhitespace(p[from]) || p[from] == ',' || p[from] == ':') {
		from++
	}
	return from
}

func encodeJSONString(s string) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// RedactStaticTerm replaces every occurrence of term in s with replacement, quoting the
// replacement when term sits in a bare (unquoted) JSON value position, and leaving an occurrence
// untouched when it's only a token-fused slice of a larger bare number/true/false/null.
//
// term has no regex capture to bound it, so only the characters immediately around each match are
// checked. A term preceded by `:`, `,` or `[` and followed by `,`, `}` or `]` — or with no
// boundary character on *either* side, i.e. term is the whole document — is a bare value
// (number/bool/null); an unquoted replacement there is invalid JSON (see CLI-1732), so the
// replacement gets quoted instead. A term missing the boundary character on only one side is an
// ambiguous fragment and is left bare rather than guessed at. A term already inside a quoted
// string is also left bare, and never treated as token-fused.
//
// A numeric term can also land mid-number in a bare position (e.g. redacting "1000" out of an
// unrelated "durationMs":10001234), and a term like "rue" can land mid-keyword (inside "true") —
// in both cases it's a slice of a larger bare token, and no amount of quoting keeps that valid, so
// the occurrence is left alone rather than corrupting the token.
//
// Exported for reuse by pkg/analytics's SanitizeStaticValues, which has the same corruption risk.
func RedactStaticTerm(s, term, replacement string) string {
	return redactTerm(s, term, replacement, false)
}

func redactTerm(s, term, replacement string, wholeWord bool) string {
	return redact(s, term, replacement, wholeWord, true)
}

func redactWholeWord(s, term, replacement string) string {
	return redact(s, term, replacement, true, false)
}

// redact optionally enforces whole-word matching and JSON-safe replacements.
func redact(s, term, replacement string, wholeWord, jsonAware bool) string {
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
		if wholeWord && isPartOfLargerToken(s, start, matchEnd) {
			if jsonAware {
				qs = qs.advance(s[end : start+1])
			}
			builder.WriteString(s[end : start+1])
			end = start + 1
			continue
		}
		if !jsonAware {
			builder.WriteString(s[end:start])
			builder.WriteString(replacement)
			end = matchEnd
			continue
		}
		qs = qs.advance(s[end:start])
		quoted := qs.inQuotes
		builder.WriteString(s[end:start])
		switch {
		case !quoted && isFusedToAdjacentBareTokenChar(s, start, matchEnd):
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

// isPartOfLargerToken reports whether s[start:end] continues into its neighbors. `-` and `.` join
// only between identifier characters, so `Content-Type` and `--target-reference` are single tokens
// while the full stop ending a sentence is not part of the last word.
func isPartOfLargerToken(s string, start, end int) bool {
	first, _ := utf8.DecodeRuneInString(s[start:end])
	before, size := utf8.DecodeLastRuneInString(s[:start])
	if isIdentifierRune(before) {
		return true
	}
	if isWordJoiner(before) && isIdentifierRune(first) {
		beyond, _ := utf8.DecodeLastRuneInString(s[:start-size])
		if isIdentifierRune(beyond) {
			return true
		}
	}

	last, _ := utf8.DecodeLastRuneInString(s[start:end])
	after, size := utf8.DecodeRuneInString(s[end:])
	if isIdentifierRune(after) {
		return true
	}
	if isWordJoiner(after) && isIdentifierRune(last) {
		beyond, _ := utf8.DecodeRuneInString(s[end+size:])
		return isIdentifierRune(beyond)
	}
	return false
}

func isIdentifierRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_'
}

func isWordJoiner(r rune) bool {
	return r == '-' || r == '.'
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
// RedactStaticTerm itself already skips this function entirely.
//
// A span with no boundary character on *either* side, once whitespace is skipped, is the entire
// document by itself — a top-level bare scalar, still a JSON value even though nothing encloses
// it. A span missing only one side's boundary is an ambiguous fragment (see RedactStaticTerm's
// start/end-of-s case) and stays unquoted rather than guessed at.
func isBareJSONValueSpan(s string, start, end int) bool {
	i := start - 1
	for i >= 0 && isJSONWhitespace(s[i]) {
		i--
	}
	j := end
	for j < len(s) && isJSONWhitespace(s[j]) {
		j++
	}
	if i < 0 && j >= len(s) {
		return true
	}

	precededByValueStart := i >= 0 && strings.ContainsRune(":,[", rune(s[i]))
	followedByValueEnd := j < len(s) && strings.ContainsRune(",}]", rune(s[j]))

	return precededByValueStart && followedByValueEnd
}

func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// isFusedToAdjacentBareTokenChar reports whether s[start:end] touches a character that only ever
// appears inside a larger unquoted JSON token — a digit or other numeric-literal character (`.`,
// `-`, `+`, `e`, `E`), or a lowercase letter — on either side, i.e. it's a slice of a bigger bare
// number/true/false/null, not a complete value by itself. jsonAware callers only reach here once
// the whole buffer is confirmed valid JSON, so an unquoted letter can only belong to one of those
// three keywords; there's no other bare token it could be part of.
func isFusedToAdjacentBareTokenChar(s string, start, end int) bool {
	precededByTokenChar := start > 0 && isJSONBareTokenChar(s[start-1])
	followedByTokenChar := end < len(s) && isJSONBareTokenChar(s[end])
	return precededByTokenChar || followedByTokenChar
}

func isJSONBareTokenChar(b byte) bool {
	return isJSONNumberChar(b) || (b >= 'a' && b <= 'z')
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
