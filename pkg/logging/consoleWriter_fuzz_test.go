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

package logging_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
)

// Terms that occur in JSON syntax and in common field values make the fuzzer reach redactions next to punctuation.
func fuzzConfig() func() configuration.Configuration {
	config := configuration.NewInMemory()
	config.Set(configuration.AUTHENTICATION_TOKEN, fakeAPIToken())
	config.Set(logging.REDACTION_TERMS, []string{"Content", "reference", "command", "monitor", "e", "1000", "true", "level"})
	return func() configuration.Configuration { return config }
}

func addConsoleWriterSeeds(f *testing.F) {
	f.Helper()
	token := fakeAPIToken()
	jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + ".e30.x"
	userinfo := strings.Join([]string{"user", "pass"}, ":")
	for _, event := range []string{
		`{"level":"debug","message":"token ` + token + `","time":"2025-09-01T00:00:00Z"}`,
		`{"level":"debug","headers":{"Authorization":["token ` + token + `"]},"message":"> request [0x1]: GET https://api.example.com/rest/self"}`,
		`{"level":"debug","message":"Content-Type: application/json","durationMs":1000,"ok":true}`,
		`{"level":"debug","message":"--target-reference=main command=monitor","args":["--remote-repo-url=https://` + userinfo + `@git.example.com/a/b","-d"]}`,
		`{"level":"debug","message":"config: _: [ 'u': 'john', p: \"x]y\" ]","n":1e10}`,
		`{"level":"debug","message":"esc \u0065 \" \\ token=abcdefgh","count":-1.5e+3}`,
		`{"level":"debug","u":"john","p":1234,"key":{"nested":[1,2,"token ` + token + `"]},"secret":null}`,
		`{"level":"debug","message":"Bearer ` + jwt + `","access_token":"` + token + `"}`,
		`{"level":"debug","e":"e","1000":1000,"reference":"reference","true":true}`,
		`{"p":-1.5e3,"u":"ends -u","token":"a\"b","key":"a\\","user":{"p":1,"u":{"a":[1,2]}},"count":[1,"p",null]}`,
	} {
		f.Add([]byte(event), "message", "token "+token, "nested", 1000.0, int64(1000))
	}
	f.Add([]byte(`{"a":"\u00e9\ud83d\ude00","b":"\u002a"}`), "e", `*"\`, "key", math.Copysign(0, -1), int64(-1))
	f.Add([]byte(`{"x":"'u': 'a\\'b', p: \"c\"d\"","y":"-p C:\\dir\\file"}`), "u", "u: john, p: x", "p", 1e-7, int64(0))
}

func plainConsoleWriterShows(event []byte) bool {
	_, err := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) { w.Out = &bytes.Buffer{} }, noColor).Write(event)
	return err == nil
}

func FuzzConsoleWriter_ShowsEveryRawEventAPlainConsoleWriterShowsWithoutTheToken(f *testing.F) {
	addConsoleWriterSeeds(f)
	config := fuzzConfig()
	f.Fuzz(func(t *testing.T, event []byte, _ string, _ string, _ string, _ float64, _ int64) {
		if !json.Valid(event) || !plainConsoleWriterShows(event) {
			t.Skip()
		}
		out := &bytes.Buffer{}

		_, err := logging.NewConsoleWriter(out, config, noColor).Write(event)

		if err != nil {
			t.Fatalf("event not shown: %v\nevent: %q", err, event)
		}
		if strings.Contains(out.String(), fakeAPIToken()) {
			t.Fatalf("token shown\nevent: %q\nshown: %q", event, out.String())
		}
	})
}

func FuzzConsoleWriter_ShowsEveryZerologEventAPlainConsoleWriterShowsWithoutTheToken(f *testing.F) {
	addConsoleWriterSeeds(f)
	config := fuzzConfig()
	f.Fuzz(func(t *testing.T, raw []byte, key string, value string, nestedKey string, number float64, integer int64) {
		out := &bytes.Buffer{}
		writer := &recordingWriter{writer: logging.NewConsoleWriter(out, config, noColor)}
		rawJSON := raw
		if !json.Valid(rawJSON) {
			rawJSON = []byte("null")
		}

		logger := zerolog.New(writer).With().Timestamp().Logger()
		logger.Debug().
			Str(key, value).
			Float64(key+"_f", number).
			Int64(nestedKey, integer).
			Dict(nestedKey+"_obj", zerolog.Dict().Str(value, key).Bytes("raw", raw).Int64(key, integer)).
			Strs("args", []string{key, value, "--" + nestedKey + "=" + value}).
			RawJSON("rawjson", rawJSON).
			Msg(value + " " + string(raw))

		if writer.err != nil {
			if plainConsoleWriterShows(writer.event) {
				t.Fatalf("event not shown: %v\nevent: %q", writer.err, writer.event)
			}
			t.Skip()
		}
		if out.Len() == 0 {
			t.Fatalf("nothing shown\nevent: %q", writer.event)
		}
		if strings.Contains(out.String(), fakeAPIToken()) {
			t.Fatalf("token shown\nevent: %q\nshown: %q", writer.event, out.String())
		}
	})
}

type recordingWriter struct {
	writer zerolog.ConsoleWriter
	event  []byte
	err    error
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.event = append([]byte(nil), p...)
	n, err := w.writer.Write(p)
	w.err = err
	return n, err
}
