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
	"strings"

	"github.com/rs/zerolog"
)

const redactMask string = "***"

type scrubbingLevelWriter struct {
	writer    zerolog.LevelWriter
	scrubDict map[string]bool
}

type scrubbingIoWriter struct {
	writer    io.Writer
	scrubDict map[string]bool
}

func (w *scrubbingLevelWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	n, err = w.writer.WriteLevel(level, scrub(p, w.scrubDict))
	return len(p), err // we return the original length, since we don't know the length of the redacted string
}

func NewScrubbingWriter(writer zerolog.LevelWriter, scrubDict map[string]bool) zerolog.LevelWriter {
	return &scrubbingLevelWriter{
		writer:    writer,
		scrubDict: scrubDict,
	}
}

func (w *scrubbingLevelWriter) Write(p []byte) (n int, err error) {
	n, err = w.writer.Write(scrub(p, w.scrubDict))
	return len(p), err // we return the original length, since we don't know the length of the redacted string
}

func scrub(p []byte, scrubDict map[string]bool) []byte {
	s := string(p)
	for term := range scrubDict {
		s = strings.Replace(s, term, redactMask, -1)
	}
	return []byte(s)
}

func NewScrubbingIoWriter(writer io.Writer, scrubDict map[string]bool) io.Writer {
	return &scrubbingIoWriter{
		writer:    writer,
		scrubDict: scrubDict,
	}
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
