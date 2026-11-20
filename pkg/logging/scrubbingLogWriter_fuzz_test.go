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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

var fuzzRedactionTerms = []string{"Content", "reference", "command", "monitor", "e", "1000", "true", "level"}

// Fake credentials are assembled at runtime so that secret scanners don't flag the test sources.
func fuzzToken() string {
	return strings.Join([]string{"f3a9c2e1", "7b4d", "4e8a", "9c1f", "2d6b8e0a4c7e"}, "-")
}

func fuzzJWT() string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + ".e30.x"
}

func fuzzURLCredentials() string {
	return strings.Join([]string{"user", "pass"}, ":")
}

func newFuzzScrubber(t *testing.T, sink *bytes.Buffer) zerolog.LevelWriter {
	t.Helper()
	dict := getDefaultDict()
	addStaticTermToDict(fuzzToken(), dict)
	w := NewScrubbingWriter(zerolog.MultiLevelWriter(sink), dict)
	scrubber, ok := w.(ScrubbingLogWriter)
	if !ok {
		t.Fatal("scrubbing writer does not accept terms")
	}
	scrubber.AddTermsToReplace(fuzzRedactionTerms)
	return w
}

func addFuzzSeeds(f *testing.F) {
	f.Helper()
	token := fuzzToken()
	seeds := []string{
		`{"level":"debug","message":"token ` + token + `","time":"2025-09-01T00:00:00Z"}`,
		`{"level":"debug","headers":{"Authorization":["token ` + token + `"]},"message":"> request [0x1]: GET https://api.example.com/rest/self"}`,
		`{"level":"debug","message":"Content-Type: application/json","durationMs":1000,"ok":true}`,
		`{"level":"debug","message":"--target-reference=main command=monitor","args":["--remote-repo-url=https://` + fuzzURLCredentials() + `@git.example.com/a/b","-d"]}`,
		`{"level":"debug","message":"config: _: [ 'u': 'john', p: \"x]y\" ]","n":1e10}`,
		`{"level":"debug","message":"esc \\u0065 \\\" \\\\ token=abcdefgh","count":-1.5e+3}`,
		`{"level":"debug","u":"john","p":1234,"key":{"nested":[1,2,"token ` + token + `"]},"secret":null}`,
		`{"level":"debug","message":"Bearer ` + fuzzJWT() + `","access_token":"` + token + `"}`,
		`{"level":"debug","e":"e","1000":1000,"reference":"reference","true":true}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s), "message", "token "+token, "nested", 1000.0, int64(1000))
	}
	f.Add([]byte(`{"a":"\u00e9\ud83d\ude00","b":"\\u002a"}`), "e", `*"\`, "key", math.Copysign(0, -1), int64(-1))
	f.Add([]byte(`{"x":"'u': 'a\\'b', p: \"c\"d\"","y":"-p C:\\dir\\file"}`), "u", "u: john, p: x", "p", 1e-7, int64(0))
}

// Every zerolog event is valid JSON, so any valid JSON input must stay valid JSON once scrubbed.
func FuzzScrubPreservesValidJSONForRawEvents(f *testing.F) {
	addFuzzSeeds(f)
	f.Fuzz(func(t *testing.T, raw []byte, _ string, _ string, _ string, _ float64, _ int64) {
		if !json.Valid(raw) {
			t.Skip()
		}
		var sink bytes.Buffer
		w := newFuzzScrubber(t, &sink)
		if _, err := w.WriteLevel(zerolog.DebugLevel, append(raw, '\n')); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if !json.Valid(sink.Bytes()) {
			t.Fatalf("valid JSON became invalid\n in: %q\nout: %q", raw, sink.Bytes())
		}
	})
}

// ConsoleWriter decodes each scrubbed event again, so the event must also survive that decode step.
func FuzzScrubPreservesValidJSONForZerologEvents(f *testing.F) {
	addFuzzSeeds(f)
	f.Fuzz(func(t *testing.T, raw []byte, key string, value string, nestedKey string, num float64, i int64) {
		var sink bytes.Buffer
		logger := zerolog.New(newFuzzScrubber(t, &sink)).With().Timestamp().Logger()
		logger.Debug().
			Str(key, value).
			Float64(key+"_f", num).
			Int64(nestedKey, i).
			Dict(nestedKey+"_obj", zerolog.Dict().Str(value, key).Bytes("raw", raw).Int64(key, i)).
			Strs("args", []string{key, value, "--" + nestedKey + "=" + value}).
			RawJSON("rawjson", validOrNull(raw)).
			Msg(value + " " + string(raw))
		out := sink.Bytes()
		if !json.Valid(out) {
			t.Fatalf("zerolog event became invalid JSON\nout: %q", out)
		}
		var console bytes.Buffer
		cw := zerolog.ConsoleWriter{Out: &console, NoColor: true}
		if _, err := cw.Write(out); err != nil {
			t.Fatalf("ConsoleWriter could not decode event: %v\nout: %q", err, out)
		}
	})
}

func validOrNull(raw []byte) []byte {
	if json.Valid(raw) {
		return raw
	}
	return []byte("null")
}
