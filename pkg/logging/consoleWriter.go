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
	"io"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// NewConsoleWriter returns a zerolog.ConsoleWriter writing to out that redacts each decoded event with a Redactor for
// config before formatting it. opts configure the writer like zerolog.NewConsoleWriter's options. A FormatPrepare set
// by opts runs before the redaction; replacing FormatPrepare on the returned writer removes the redaction.
func NewConsoleWriter(out io.Writer, config configuration.Configuration, opts ...func(w *zerolog.ConsoleWriter)) zerolog.ConsoleWriter {
	redactor := NewRedactor(config)
	w := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) { w.Out = out })
	for _, opt := range opts {
		opt(&w)
	}
	prepare := w.FormatPrepare
	w.FormatPrepare = func(event map[string]interface{}) error {
		if prepare != nil {
			if err := prepare(event); err != nil {
				return err
			}
		}
		redactor.current().redactEvent(event)
		return nil
	}
	return w
}
