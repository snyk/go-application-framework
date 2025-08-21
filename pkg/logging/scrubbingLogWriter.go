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

func GetScrubDictFromConfig(config configuration.Configuration) ScrubbingDict {
	dict := getDefaultDict()
	addRegexTermToDict(config.GetString(configuration.AUTHENTICATION_TOKEN), 0, dict)
	addRegexTermToDict(config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN), 0, dict)
	addRegexTermToDict(config.GetString(auth.PARAMETER_CLIENT_SECRET), 0, dict)
	addRegexTermToDict(config.GetString(auth.PARAMETER_CLIENT_ID), 0, dict)
	token, err := auth.GetOAuthToken(config)
	if err != nil || token == nil {
		return dict
	}
	addRegexTermToDict(token.AccessToken, 0, dict)
	addRegexTermToDict(token.RefreshToken, 0, dict)
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
	s = `(?s)_:\s*\[(?<everything_inside_hard_brackets>.*)\]`
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
	s = fmt.Sprintf(`(?im)'[%s]=(?<value>.*)'`, shortForm)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	// Specific short-form scrubbing of the JSON-ish log structures
	// Appear in the snyk-config debug logging as various constellations of { 'u': 'john.doe', } with or without quotes,
	// and values can contain spaces, double and/or single quotes.

	s = fmt.Sprintf(`(?i)(?<short_form_key>\b[%s]\b)[,'":]+\s*(?:['"](?<short_form_value>.*)['"]|([^,'"\s]+))[,}]?`, shortForm)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	// CLI argument-style-specific scrubbing
	// Many cases are already covered by the JSON scrubbing above, thus this might seem incomplete.
	// Refer to the unit tests for the full set of covered cases.
	s = fmt.Sprintf(`(?im)\-[%s][\s=](?<short_form_value>\S*)`, shortForm)
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

func scrub(p []byte, scrubDict ScrubbingDict) []byte {
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
			s = strings.ReplaceAll(s, entry.replace, SANITIZE_REPLACEMENT_STRING)
			continue
		}
		// then scrub from the regex list
		matches := entry.regex.FindAllStringSubmatch(s, -1)
		for _, match := range matches {
			if entry.groupToRedact >= len(match) || match[entry.groupToRedact] == "" {
				continue
			}
			s = strings.Replace(s, match[entry.groupToRedact], SANITIZE_REPLACEMENT_STRING, -1)
		}
	}
	return []byte(s)
}

func (w *scrubbingIoWriter) Write(p []byte) (int, error) {
	// lock for dict changes, but allow unlimited readers
	w.m.RLock()
	defer w.m.RUnlock()
	return internalWrite(w.scrubDict, p, w.writer.Write)
}

func internalWrite(dict ScrubbingDict, p []byte, writeFunc func(p []byte) (int, error)) (int, error) {
	scrubbedDataWritten := 0
	scrubbedData := scrub(p, dict)
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
