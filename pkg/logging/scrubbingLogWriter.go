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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

const redactMask string = "***"

type ScrubbingLogWriter interface {
	AddTerm(term string, matchGroup int)
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
	addMandatoryMasking(dict)
	return dict
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

func addMandatoryMasking(dict ScrubbingDict) ScrubbingDict {
	const charGroup = "[a-zA-Z0-9-_:.]{6,}"
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
	// github
	s = fmt.Sprintf("(access_token=)(%s)&", charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}
	s = fmt.Sprintf("(refresh_token=)(%s)&", charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}
	s = fmt.Sprintf(`("token":)"(%s)"`, charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	s = fmt.Sprintf(`(SNYK_TOKEN)=(%s)`, charGroup)
	dict[s] = scrubStruct{
		groupToRedact: 2,
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
	for _, entry := range scrubDict {
		matches := entry.regex.FindAllStringSubmatch(s, -1)
		for _, match := range matches {
			s = strings.Replace(s, match[entry.groupToRedact], redactMask, -1)
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

	for errorsSeen := 0; scrubbedDataWritten < len(scrubbedData); {
		written, err := writeFunc(scrubbedData[scrubbedDataWritten:])
		scrubbedDataWritten += written

		if err != nil {
			errorsSeen++
		}

		// circuit breaker
		if errorsSeen > 10 {
			return len(p), err
		}

		// exponential backoff
		time.Sleep(time.Millisecond * time.Duration(errorsSeen*errorsSeen*10))
	}

	return len(p), nil // we return the original length, since we don't know the length of the redacted string
}
