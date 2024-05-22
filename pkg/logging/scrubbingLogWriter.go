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

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const redactMask string = "***"

type ScrubbingDict map[string]bool

type scrubbingLevelWriter struct {
	writer     zerolog.LevelWriter
	scrubDict  ScrubbingDict
	regexCache map[string]*regexp.Regexp
}

type scrubbingIoWriter struct {
	writer     io.Writer
	scrubDict  ScrubbingDict
	regexCache map[string]*regexp.Regexp
}

func GetScrubDictFromConfig(config configuration.Configuration) ScrubbingDict {
	dict := getDefaultDict()
	dict[config.GetString(configuration.AUTHENTICATION_TOKEN)] = true
	return dict
}

func getDefaultDict() ScrubbingDict {
	dict := ScrubbingDict{}
	addMandatoryMasking(dict)
	return dict
}

func (w *scrubbingLevelWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	_, err := w.writer.WriteLevel(level, scrub(p, w.regexCache))
	return len(p), err // we return the original length, since we don't know the length of the redacted string
}

func NewScrubbingWriter(writer zerolog.LevelWriter, scrubDict ScrubbingDict) zerolog.LevelWriter {
	dict := addMandatoryMasking(scrubDict)
	regexCache := compileRegularExpressions(dict)
	levelWriter := scrubbingLevelWriter{
		writer:     writer,
		scrubDict:  dict,
		regexCache: regexCache,
	}
	return &levelWriter
}

func compileRegularExpressions(dict ScrubbingDict) map[string]*regexp.Regexp {
	regexCache := make(map[string]*regexp.Regexp)
	for term := range dict {
		if term != "" {
			regexCache[term] = regexp.MustCompile(term)
		}
	}
	return regexCache
}

func addMandatoryMasking(dict ScrubbingDict) ScrubbingDict {
	dict["//.*:.*@"] = true
	return dict
}

func (w *scrubbingLevelWriter) Write(p []byte) (int, error) {
	_, err := w.writer.Write(scrub(p, w.regexCache))
	return len(p), err // we return the original length, since we don't know the length of the redacted string
}

func scrub(p []byte, regexCache map[string]*regexp.Regexp) []byte {
	s := string(p)
	for _, re := range regexCache {
		s = re.ReplaceAllLiteralString(s, redactMask)
	}
	return []byte(s)
}

func NewScrubbingIoWriter(writer io.Writer, scrubDict ScrubbingDict) io.Writer {
	dict := addMandatoryMasking(scrubDict)
	regexCache := compileRegularExpressions(dict)
	return &scrubbingIoWriter{
		writer:     writer,
		scrubDict:  addMandatoryMasking(scrubDict),
		regexCache: regexCache,
	}
}

func (w *scrubbingIoWriter) Write(p []byte) (n int, err error) {
	_, err = w.writer.Write(scrub(p, w.regexCache))
	if err != nil {
		// in case of an error of the underlying writer, we return zero bytes written,
		// since it is difficult to map back to the unredacted length.
		return 0, err
	}

	return len(p), err
}
