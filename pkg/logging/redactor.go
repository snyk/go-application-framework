/*
 * © 2026 Snyk Limited
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
	"maps"
	"os/user"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

const SANITIZE_REPLACEMENT_STRING string = "***"

// REDACTION_TERMS configures literal terms redacted only as whole tokens.
const REDACTION_TERMS string = "internal_redaction_terms"

// minDeviceTokenTermLength mirrors machinecredential's floor for secret terms: a shorter value would
// also redact unrelated text.
const minDeviceTokenTermLength = 16

// Redactor removes credentials from log text. On every redaction it reads the credentials and REDACTION_TERMS of the
// configuration its provider returns, so values set after it was created and a configuration the provider switches to
// are covered, and it keeps redacting values that have since been replaced, such as a rotated token or the secrets of a
// configuration the provider no longer returns. Redaction is a best effort on known shapes of credentials, not a
// guarantee. A Redactor is safe for concurrent use. Default functions of the configuration for the values it reads must
// not log through a writer that redacts with this Redactor, because that redaction reads them again.
type Redactor struct {
	config func() configuration.Configuration

	mu      sync.Mutex
	secrets map[string]struct{}
	terms   map[string]struct{}
	rules   *rules
}

// NewRedactor returns a Redactor for the credentials and REDACTION_TERMS of the configuration config returns. config is
// called on every redaction, from any goroutine, and a nil configuration adds nothing to redact. The name of the
// current OS user is redacted as a term, too.
func NewRedactor(config func() configuration.Configuration) *Redactor {
	r := &Redactor{config: config, secrets: map[string]struct{}{}, terms: map[string]struct{}{}}
	if u, err := user.Current(); err == nil {
		addAll(r.terms, []string{u.Username})
	}
	r.rules = newRules(r.secrets, r.terms)
	return r
}

// Redact returns s with the credentials it finds replaced by SANITIZE_REPLACEMENT_STRING.
func (r *Redactor) Redact(s string) string {
	return r.current().redact(s)
}

// current returns the rules for the configuration's present values. The configuration is read without holding the
// lock, because its default functions are callbacks that can take arbitrarily long.
func (r *Redactor) current() *rules {
	var secrets, terms []string
	if config := r.config(); config != nil {
		secrets = secretsFromConfig(config)
		terms = config.GetStringSlice(REDACTION_TERMS)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	addedSecrets := addAll(r.secrets, secrets)
	addedTerms := addAll(r.terms, terms)
	if addedSecrets || addedTerms {
		r.rules = newRules(r.secrets, r.terms)
	}
	return r.rules
}

func addAll(set map[string]struct{}, values []string) bool {
	added := false
	for _, v := range values {
		if _, ok := set[v]; !ok && v != "" {
			set[v] = struct{}{}
			added = true
		}
	}
	return added
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

// rules is an immutable snapshot of what a Redactor redacts.
type rules struct {
	secrets *strings.Replacer
	terms   []string
}

func newRules(secrets, terms map[string]struct{}) *rules {
	// Longest first, so a secret containing another one, such as a PEM and its lines, is redacted whole.
	byLength := func(set map[string]struct{}) []string {
		values := make([]string, 0, len(set))
		for v := range set {
			values = append(values, v)
		}
		slices.SortFunc(values, func(a, b string) int { return len(b) - len(a) })
		return values
	}
	var replacements []string
	for _, secret := range byLength(secrets) {
		replacements = append(replacements, secret, SANITIZE_REPLACEMENT_STRING)
	}
	return &rules{secrets: strings.NewReplacer(replacements...), terms: byLength(terms)}
}

var (
	urlUserinfo = regexp.MustCompile(`(?i)(https?://)[^\s/"'?#]+@`)
	snykPAT     = regexp.MustCompile(auth.PAT_REGEX)
	githubToken = regexp.MustCompile(`\b(gh[ps]_|github_pat_)\w+`)
	authScheme  = regexp.MustCompile(`(?i)\b(bearer|basic|negotiate|token)\s+([\w` + regexp.QuoteMeta(credentialPunctuation) + `]+)`)
)

// credentialPunctuation includes "*" because an earlier rule can already have replaced part of a credential, such as
// the payload of a Snyk PAT.
const credentialPunctuation = "-:.=/+~*"

func (rl *rules) redact(s string) string {
	s = rl.secrets.Replace(s)
	s = urlUserinfo.ReplaceAllString(s, "${1}"+SANITIZE_REPLACEMENT_STRING+"@")
	s = snykPAT.ReplaceAllString(s, "${1}."+SANITIZE_REPLACEMENT_STRING)
	s = githubToken.ReplaceAllString(s, "${1}"+SANITIZE_REPLACEMENT_STRING)
	s = redactKeyValues(s)
	s = redactAuthSchemes(s)
	for _, term := range rl.terms {
		s = redactWholeToken(s, term)
	}
	return s
}

// spanWriter builds a copy of a string with some spans replaced, in one left-to-right pass.
type spanWriter struct {
	s       string
	b       strings.Builder
	written int
}

func (r *spanWriter) replace(start, end int) {
	r.b.WriteString(r.s[r.written:start])
	r.b.WriteString(SANITIZE_REPLACEMENT_STRING)
	r.written = end
}

func (r *spanWriter) String() string {
	if r.written == 0 {
		return r.s
	}
	r.b.WriteString(r.s[r.written:])
	return r.b.String()
}

// redactKeyValues redacts the value of each `key: value` or `key=value` pair in s whose key is sensitive, such as
// `"password":"x"`, `token=x&` or `u: x`, and of a sensitive command line flag, such as `-p x`. A key or value can be
// quoted with ", ' or an escaped quote. After a key that isn't sensitive, the scan continues behind the separator,
// so a pair nested in the value is found, too.
func redactKeyValues(s string) string {
	r := &spanWriter{s: s}
	for i := 0; i < len(s); {
		if i > 0 && isKeyChar(s[i-1]) {
			i++
			continue
		}
		i = redactPairAt(r, i)
	}
	return r.String()
}

// redactPairAt redacts the value if a pair with a sensitive key starts at i, and returns where the scan continues.
func redactPairAt(r *spanWriter, i int) int {
	s := r.s
	quote := quoteAt(s, i)
	keyStart := i + len(quote)
	keyEnd := keyStart
	for keyEnd < len(s) && isKeyChar(s[keyEnd]) {
		keyEnd++
	}
	if keyEnd == keyStart {
		return i + 1
	}
	if quote != "" && !strings.HasPrefix(s[keyEnd:], quote) {
		return keyStart
	}
	key := s[keyStart:keyEnd]
	next := keyEnd + len(quote)
	valueStart := skipSpaces(s, next)
	switch {
	case valueStart < len(s) && (s[valueStart] == ':' || s[valueStart] == '='):
		if !IsSensitiveFieldName(key) {
			return valueStart + 1
		}
		valueStart = skipSpaces(s, valueStart+1)
	case quote == "" && key[0] == '-' && valueStart > next && IsSensitiveFieldName(key):
	default:
		return keyEnd
	}
	start, end := valueSpan(s, valueStart)
	if quoteAt(s, valueStart) == "" && strings.Contains(strings.ToLower(key), "cookie") {
		end = cookieHeaderEnd(s, start, strings.HasPrefix(s[valueStart:], "["))
	}
	if end > start {
		r.replace(start, end)
	}
	return max(end, valueStart)
}

// valueSpan returns the span of the value starting at i. A quoted value ends at the first closing quote followed by
// whitespace, a delimiter such as "," or "}", or the end of s, so a quote inside the value doesn't end it, and it runs
// to the end of s without one. An unquoted value ends at whitespace or "&", without trailing punctuation. When it is an
// auth scheme, such as in `Authorization: Bearer x`, the credential after it is the value.
func valueSpan(s string, i int) (int, int) {
	if quote := quoteAt(s, i); quote != "" {
		start := i + len(quote)
		return start, closingQuote(s, start, quote)
	}
	if i < len(s) && s[i] == '[' {
		i++
	}
	end := unquotedEnd(s, i)
	if authSchemes[strings.ToLower(s[i:end])] {
		if credentialStart := skipSpaces(s, end); credentialStart > end {
			return credentialStart, credentialEnd(s, credentialStart)
		}
	}
	return i, end
}

// cookieHeaderEnd returns the end of a cookie header's value starting at i: the end of the line, or the closing "]" of
// a bracketed value, because every cookie in it is a credential.
func cookieHeaderEnd(s string, i int, bracketed bool) int {
	stops := "\r\n"
	if bracketed {
		stops += "]"
	}
	if n := strings.IndexAny(s[i:], stops); n >= 0 {
		return i + n
	}
	return len(s)
}

var authSchemes = map[string]bool{"bearer": true, "basic": true, "negotiate": true, "token": true}

func unquotedEnd(s string, i int) int {
	end := i
	for end < len(s) && !isSpace(s[end]) && s[end] != '&' {
		end++
	}
	return trimPunctuation(s, i, end)
}

func credentialEnd(s string, i int) int {
	for i < len(s) && (isWordChar(s[i]) || strings.IndexByte(credentialPunctuation, s[i]) >= 0) {
		i++
	}
	return i
}

func trimPunctuation(s string, start, end int) int {
	for end > start && strings.IndexByte(",;\"'])}", s[end-1]) >= 0 {
		end--
	}
	return end
}

func quoteAt(s string, i int) string {
	for _, quote := range []string{`"`, `'`, `\"`, `\'`} {
		if strings.HasPrefix(s[i:], quote) {
			return quote
		}
	}
	return ""
}

func closingQuote(s string, start int, quote string) int {
	if len(quote) > 1 {
		if n := strings.Index(s[start:], quote); n >= 0 {
			return start + n
		}
		return len(s)
	}
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case quote[0]:
			if i+1 == len(s) || isSpace(s[i+1]) || strings.IndexByte(",}];&", s[i+1]) >= 0 {
				return i
			}
		}
	}
	return len(s)
}

// redactAuthSchemes redacts the credential after an auth scheme in prose, such as `retrying with Bearer x`, when it
// looks like one, so `Basic authentication` stays readable.
func redactAuthSchemes(s string) string {
	r := &spanWriter{s: s}
	for pos := 0; pos < len(s); {
		m := authScheme.FindStringSubmatchIndex(s[pos:])
		if m == nil {
			break
		}
		start, end := pos+m[4], pos+m[5]
		if !looksLikeCredential(s[start:end]) {
			pos += m[3]
			continue
		}
		r.replace(start, end)
		pos = end
	}
	return r.String()
}

func looksLikeCredential(value string) bool {
	if len(value) < 6 {
		return false
	}
	if strings.ContainsAny(value, "0123456789=+/") {
		return true
	}
	for i := 1; i < len(value); i++ {
		if unicode.IsLower(rune(value[i-1])) && unicode.IsUpper(rune(value[i])) {
			return true
		}
	}
	return false
}

// redactWholeToken redacts each occurrence of term in s that is a whole token: not next to a letter, digit or "_" of any
// script, nor joined to one by a single "-" or ".", so the term "Content" leaves "Content-Type" alone.
func redactWholeToken(s, term string) string {
	r := &spanWriter{s: s}
	for from := 0; ; {
		n := strings.Index(s[from:], term)
		if n < 0 {
			break
		}
		start, end := from+n, from+n+len(term)
		if joinedBefore(s[:start]) || joinedAfter(s[end:]) {
			from = start + 1
			continue
		}
		r.replace(start, end)
		from = end
	}
	return r.String()
}

// joinedBefore reports whether before ends in a letter, digit or "_", or in a "-" or "." preceded by one.
func joinedBefore(before string) bool {
	r, n := utf8.DecodeLastRuneInString(before)
	if isWordRune(r) {
		return true
	}
	if r != '-' && r != '.' {
		return false
	}
	r, _ = utf8.DecodeLastRuneInString(before[:len(before)-n])
	return isWordRune(r)
}

// joinedAfter reports whether after starts with a letter, digit or "_", or with a "-" or "." followed by one.
func joinedAfter(after string) bool {
	r, n := utf8.DecodeRuneInString(after)
	if isWordRune(r) {
		return true
	}
	if r != '-' && r != '.' {
		return false
	}
	r, _ = utf8.DecodeRuneInString(after[n:])
	return isWordRune(r)
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isWordChar(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func isKeyChar(c byte) bool {
	return isWordChar(c) || c == '-' || c == '.'
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func skipSpaces(s string, i int) int {
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	return i
}

// redactEvent redacts a decoded log event in place. Secrets are redacted in field names, too, and the value of a
// sensitive field is replaced as a whole.
func (rl *rules) redactEvent(event map[string]interface{}) {
	for _, name := range slices.Collect(maps.Keys(event)) {
		value := event[name]
		if IsSensitiveFieldName(name) {
			value = SANITIZE_REPLACEMENT_STRING
		} else {
			value = rl.redactValue(value)
		}
		if redactedName := rl.secrets.Replace(name); redactedName != name {
			delete(event, name)
			name = redactedName
		}
		event[name] = value
	}
}

func (rl *rules) redactValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return rl.redact(v)
	case json.Number:
		if redacted := rl.redact(string(v)); redacted != string(v) {
			return redacted
		}
	case map[string]interface{}:
		rl.redactEvent(v)
	case []interface{}:
		for i := range v {
			v[i] = rl.redactValue(v[i])
		}
	}
	return value
}

// IsSensitiveFieldName reports whether a field or header of this name holds a credential or personal data, such as
// apiKey, client_secret, Set-Cookie, userName or passwordHash. The name is sensitive when one of its words, split at
// case changes and the separators "-", "_", "." and space, is a credential word such as password or token, or a
// qualified key such as "signing key", or when the name without separators ends in one, such as apikey.
func IsSensitiveFieldName(name string) bool {
	words := fieldNameWords(name)
	for i, word := range words {
		word = singular(word)
		if sensitiveNameWords[word] || word == "key" && i > 0 && sensitiveKeyQualifiers[words[i-1]] {
			return true
		}
	}
	n := strings.Map(func(r rune) rune {
		if strings.ContainsRune("-_. ", r) {
			return -1
		}
		return unicode.ToLower(r)
	}, name)
	if strings.HasSuffix(n, "headers") {
		return true
	}
	if len(n) > 2 {
		n = strings.TrimSuffix(n, "s")
	}
	if n == "u" || n == "p" || n == "key" {
		return true
	}
	for _, suffix := range sensitiveNameSuffixes {
		if strings.HasSuffix(n, suffix) {
			return true
		}
	}
	return false
}

// fieldNameWords splits a name into lowercase words at separators and case changes, so that both apiKey and APIKey
// are "api" and "key".
func fieldNameWords(name string) []string {
	var words []string
	var word []rune
	runes := []rune(name)
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			words, word = appendWord(words, word), nil
			continue
		}
		if unicode.IsUpper(r) && len(word) > 0 && (!unicode.IsUpper(runes[i-1]) || i+1 < len(runes) && unicode.IsLower(runes[i+1])) {
			words, word = appendWord(words, word), nil
		}
		word = append(word, unicode.ToLower(r))
	}
	return appendWord(words, word)
}

func appendWord(words []string, word []rune) []string {
	if len(word) == 0 {
		return words
	}
	return append(words, string(word))
}

func singular(word string) string {
	if len(word) > 2 {
		return strings.TrimSuffix(word, "s")
	}
	return word
}

var sensitiveNameWords = map[string]bool{
	"secret": true, "password": true, "passwd": true, "passwort": true, "passcode": true, "passphrase": true, "pwd": true,
	"token": true, "credential": true, "authorization": true, "cookie": true,
}

var sensitiveKeyQualifiers = map[string]bool{
	"private": true, "signing": true, "encryption": true, "api": true, "access": true, "session": true, "client": true,
	"fleet": true, "license": true, "ssh": true, "secret": true,
}

var sensitiveNameSuffixes = []string{
	"password", "passwd", "passwort", "passphrase", "passcode", "pwd",
	"secret", "token", "credential", "authorization", "cookie",
	"apikey", "accesskey", "privatekey", "secretkey", "sessionkey", "fleetkey", "licensekey", "sshkey",
	"username", "user", "login",
}
