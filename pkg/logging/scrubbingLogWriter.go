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
	"io"
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

// EXACT_SCRUB_LIST is a list of terms to scrub with exact matching.
var EXACT_SCRUB_LIST = []string{
	"u",
	"p",
	"pw",
	"path",
	"creds",
}

// FUZZY_SCRUB_RE is a regex pattern used to scrub with fuzzy matching
var FUZZY_SCRUB_RE = regexp.MustCompile("(?i)(headers|user|passw|token|key|secret|pat|creden)")

type ScrubbingLogWriter interface {
	AddTerm(term string, matchGroup int)
	// AddArgs adds all args as a key-value pair to check for scrubbing.
	// Any args that match the scrub list will be added to the scrubbing dictionary.
	AddArgs(args map[string]string)
	RemoveTerm(term string)
}

type scrubStruct struct {
	groupToRedact int
	regex         *regexp.Regexp
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
	levelWriter := scrubbingLevelWriter{
		writer:    writer,
		scrubDict: scrubDict,
	}
	return &levelWriter
}

func NewScrubbingIoWriter(writer io.Writer, scrubDict ScrubbingDict) io.Writer {
	return &scrubbingIoWriter{
		writer:    writer,
		scrubDict: scrubDict,
	}
}

func (w *scrubbingIoWriter) AddArgs(args map[string]string) {
	filteredArgs := filterArgs(args)

	// lock for dict readers and writers
	w.m.Lock()
	defer w.m.Unlock()

	// add the filtered args to the scrubbing dictionary
	for _, v := range filteredArgs {
		addTermToDict(v, 0, w.scrubDict)
	}
}

func (w *scrubbingIoWriter) AddTerm(term string, matchGroup int) {
	// lock for dict readers and writers
	w.m.Lock()
	defer w.m.Unlock()
	addTermToDict(term, matchGroup, w.scrubDict)
}

func addTermToDict(term string, matchGroup int, dict ScrubbingDict) {
	if term != "" {
		dict[term] = scrubStruct{matchGroup, regexp.MustCompile(term)}
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
	addTermToDict(config.GetString(configuration.AUTHENTICATION_TOKEN), 0, dict)
	addTermToDict(config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN), 0, dict)
	addTermToDict(config.GetString(auth.PARAMETER_CLIENT_SECRET), 0, dict)
	addTermToDict(config.GetString(auth.PARAMETER_CLIENT_ID), 0, dict)
	token, err := auth.GetOAuthToken(config)
	if err != nil || token == nil {
		return dict
	}
	addTermToDict(token.AccessToken, 0, dict)
	addTermToDict(token.RefreshToken, 0, dict)
	return dict
}

func getDefaultDict() ScrubbingDict {
	dict := ScrubbingDict{}
	return dict
}

func (w *scrubbingLevelWriter) AddArgs(args map[string]string) {
	filteredArgs := filterArgs(args)

	// lock for dict readers and writers
	w.m.Lock()
	defer w.m.Unlock()

	// add the filtered args to the scrubbing dictionary
	for _, v := range filteredArgs {
		addTermToDict(v, 0, w.scrubDict)
	}
}

func (w *scrubbingLevelWriter) AddTerm(term string, matchGroup int) {
	// lock for dict readers and writers
	w.m.Lock()
	defer w.m.Unlock()
	addTermToDict(term, matchGroup, w.scrubDict)
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

// filterArgs filters the args map to only include args that match the scrubbing criteria.
func filterArgs(args map[string]string) []string {
	argsMap := make(map[string]string, len(args))

	// check for exact matches
	for _, name := range EXACT_SCRUB_LIST {
		if v, ok := args[strings.ToLower(name)]; ok {
			argsMap[v] = v
		}
		if v, ok := args[strings.ToUpper(name)]; ok {
			argsMap[v] = v
		}
	}

	// check for fuzzy matches (case insensitive)
	for k, v := range args {
		if FUZZY_SCRUB_RE.MatchString(k) {
			argsMap[v] = v
		}
	}

	// return as a slice of values
	filteredArgs := make([]string, 0, len(argsMap))
	for _, v := range argsMap {
		filteredArgs = append(filteredArgs, v)
	}
	return filteredArgs
}
