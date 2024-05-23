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
	"strings"
	"sync"

	"github.com/rs/zerolog"

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
	m         sync.Mutex
	writer    zerolog.LevelWriter
	scrubDict ScrubbingDict
}

type scrubbingIoWriter struct {
	m         sync.Mutex
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
	w.m.Lock()
	defer w.m.Unlock()
	delete(w.scrubDict, term)
}

func GetScrubDictFromConfig(config configuration.Configuration) ScrubbingDict {
	dict := getDefaultDict()
	addTermToDict(config.GetString(configuration.AUTHENTICATION_TOKEN), 0, dict)
	return dict
}

func getDefaultDict() ScrubbingDict {
	dict := ScrubbingDict{}
	addMandatoryMasking(dict)
	return dict
}

func (w *scrubbingLevelWriter) AddTerm(term string, matchGroup int) {
	w.m.Lock()
	defer w.m.Unlock()
	addTermToDict(term, matchGroup, w.scrubDict)
}

func (w *scrubbingLevelWriter) RemoveTerm(term string) {
	w.m.Lock()
	defer w.m.Unlock()
	delete(w.scrubDict, term)
}

func (w *scrubbingLevelWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	_, err := w.writer.WriteLevel(level, scrub(p, w.scrubDict))
	return len(p), err // we return the original length, since we don't know the length of the redacted string
}

func addMandatoryMasking(dict ScrubbingDict) ScrubbingDict {
	s := `(http(s)?://)((.+?):(.+?))@(\S+)`
	dict[s] = scrubStruct{
		groupToRedact: 3,
		regex:         regexp.MustCompile(s),
	}
	s = `([t|T]oken )([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}
	s = "(gh[ps])_([a-zA-Z0-9]{36})"
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}
	s = "(github_pat_)([a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})"
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}
	// github
	s = "(access_token=)(.*)&"
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}
	s = "(refresh_token=)(.*)&"
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}
	s = `("token":)"(.*)"`
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}

	s = `(SNYK_TOKEN)=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`
	dict[s] = scrubStruct{
		groupToRedact: 2,
		regex:         regexp.MustCompile(s),
	}
	return dict
}

func (w *scrubbingLevelWriter) Write(p []byte) (int, error) {
	_, err := w.writer.Write(scrub(p, w.scrubDict))
	return len(p), err // we return the original length, since we don't know the length of the redacted string
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

func (w *scrubbingIoWriter) Write(p []byte) (n int, err error) {
	_, err = w.writer.Write(scrub(p, w.scrubDict))
	if err != nil {
		// in case of an error of the underlying writer, we return zero bytes written,
		// since it is difficult to map back to the unredacted length.
		return 0, err
	}

	return len(p), err
}
