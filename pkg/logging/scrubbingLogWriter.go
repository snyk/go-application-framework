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

type scrubbingLevelWriter struct {
	writer    zerolog.LevelWriter
	scrubDict map[string]bool
}

type scrubbingIoWriter struct {
	writer    io.Writer
	scrubDict map[string]bool
}

func (w *scrubbingLevelWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	return w.writer.WriteLevel(level, scrub(p, w.scrubDict))
}

func NewScrubbingWriter(writer zerolog.LevelWriter, scrubDict map[string]bool) zerolog.LevelWriter {
	return &scrubbingLevelWriter{
		writer:    writer,
		scrubDict: scrubDict,
	}
}

func (w *scrubbingLevelWriter) Write(p []byte) (n int, err error) {
	return w.writer.Write(scrub(p, w.scrubDict))
}

func scrub(p []byte, scrubDict map[string]bool) []byte {
	s := string(p)
	for term := range scrubDict {
		s = strings.Replace(s, term, "***", -1)
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
	return w.writer.Write(scrub(p, w.scrubDict))
}
