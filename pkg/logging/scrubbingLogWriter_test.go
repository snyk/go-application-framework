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
	"bytes"
	"encoding/json"
	"fmt"
	"os/user"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

type mockWriter struct {
	written         []byte
	Error           error
	MaxBytesToWrite int
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	if m.MaxBytesToWrite > 0 {
		length := min(m.MaxBytesToWrite, len(p))
		m.written = append(m.written, p[0:length]...)
		return m.MaxBytesToWrite, m.Error
	}

	m.written = p
	return len(p), m.Error
}

func (m *mockWriter) WriteLevel(_ zerolog.Level, p []byte) (n int, err error) {
	m.written = p
	return len(p), m.Error
}

func TestScrubbingWriter_Write(t *testing.T) {
	mockWriter := &mockWriter{}
	config := configuration.NewInMemory()
	config.Set(configuration.AUTHENTICATION_TOKEN, "password")

	writer := NewScrubbingWriter(mockWriter, GetScrubDictFromConfig(config))

	n, err := writer.Write([]byte("password"))

	assert.Nil(t, err)
	assert.Equal(t, len("password"), n)

	require.Equal(t, "***", string(mockWriter.written), "password should be scrubbed")
}

func TestScrubbingWriter_WriteLevel(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(configuration.AUTHENTICATION_TOKEN, "password")
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "bearertoken")
	config.Set(auth.PARAMETER_CLIENT_ID, "oauthclientid")
	config.Set(auth.PARAMETER_CLIENT_SECRET, "oauthclientsecret")

	mockWriter := &mockWriter{}
	writer := NewScrubbingWriter(mockWriter, GetScrubDictFromConfig(config))

	s := "These are the secrets: password, bearertoken, oauthclientid, oauthclientsecret"
	expected := "These are the secrets: ***, ***, ***, ***"

	n, err := writer.WriteLevel(zerolog.InfoLevel, []byte(s))
	assert.Nil(t, err)
	assert.Equal(t, len(s), n)

	require.Equal(t, expected, string(mockWriter.written), "password should be scrubbed")
}

func TestScrubbingWriter_GetScrubDictFromConfig_RedactionTerms(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(REDACTION_TERMS, []string{"my-literal-secret"})

	mockWriter := &mockWriter{}
	writer := NewScrubbingWriter(mockWriter, GetScrubDictFromConfig(config))

	n, err := writer.Write([]byte("my-literal-secret"))

	assert.Nil(t, err)
	assert.Equal(t, len("my-literal-secret"), n)
	require.Equal(t, "***", string(mockWriter.written), "configured redaction term should be scrubbed")
}

// TestScrubbingWriter_Write_JSONAwarenessFollowsInputValidity guards the fix for a real corruption
// path: a consumer that wraps this writer's output in a non-JSON formatter (e.g. zerolog's
// ConsoleWriter, which decodes the JSON zerolog encodes and re-emits human-readable prose before
// forwarding it here) was getting the JSON-aware bare-value quoting applied to that prose, which
// has no JSON to protect — injecting stray quote characters into a log line whenever a redacted
// term happened to sit right next to a `:` or `,`. internalWrite now decides jsonAware from p's own
// validity rather than assuming every Write is JSON.
func TestScrubbingWriter_Write_JSONAwarenessFollowsInputValidity(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(REDACTION_TERMS, []string{"12345"})
	dict := GetScrubDictFromConfig(config)

	t.Run("valid JSON input still gets bare-value quoting", func(t *testing.T) {
		mockWriter := &mockWriter{}
		writer := NewScrubbingWriter(mockWriter, dict)

		_, err := writer.Write([]byte(`{"count":12345}`))
		assert.NoError(t, err)
		assert.Equal(t, `{"count":"***"}`, string(mockWriter.written))
	})

	t.Run("non-JSON input is left bare instead of stray-quoted", func(t *testing.T) {
		mockWriter := &mockWriter{}
		writer := NewScrubbingWriter(mockWriter, dict)

		_, err := writer.Write([]byte("count:12345, retrying"))
		assert.NoError(t, err)
		assert.Equal(t, "count:***, retrying", string(mockWriter.written))
	})
}

func TestScrubbingIoWriter(t *testing.T) {
	scrubDict := map[string]scrubStruct{
		"token":  {0, regexp.MustCompile("token"), ""},
		"secret": {0, regexp.MustCompile("secret"), ""},
	}

	pattern := "%s for my account, including my %s"
	patternWithSecret := fmt.Sprintf(pattern, "secret", "token")
	patternWithMaskedSecret := fmt.Sprintf(pattern, SANITIZE_REPLACEMENT_STRING, SANITIZE_REPLACEMENT_STRING)

	bufioWriter := bytes.NewBufferString("")
	writer := NewScrubbingIoWriter(bufioWriter, scrubDict)

	// invoke method under test
	n, err := writer.Write([]byte(patternWithSecret))
	require.NoError(t, err)
	require.Equal(t, len(patternWithSecret), n)
	require.Equal(t, patternWithMaskedSecret, bufioWriter.String(), "secret should be scrubbed")

	// now remove term token from dict and test again
	t.Run("now remove term token from dict and test again", func(t *testing.T) {
		bufioWriter = bytes.NewBufferString("")
		writer = NewScrubbingIoWriter(bufioWriter, scrubDict)

		writer.(ScrubbingLogWriter).RemoveTerm("token")  //nolint:errcheck //in this test, the type is clear
		writer.(ScrubbingLogWriter).RemoveTerm("secret") //nolint:errcheck //in this test, the type is clear

		n, err = writer.Write([]byte(patternWithSecret))
		require.NoError(t, err)
		require.Equal(t, len(patternWithSecret), n)
		require.Equal(t, patternWithSecret, bufioWriter.String())
	})

	// now re-add
	t.Run("now re-add", func(t *testing.T) {
		bufioWriter = bytes.NewBufferString("")
		writer = NewScrubbingIoWriter(bufioWriter, scrubDict)
		writer.(ScrubbingLogWriter).AddTerm("token", 0)  //nolint:errcheck //in this test, the type is clear
		writer.(ScrubbingLogWriter).AddTerm("secret", 0) //nolint:errcheck //in this test, the type is clear

		n, err = writer.Write([]byte(patternWithSecret))
		require.NoError(t, err)
		require.Equal(t, len(patternWithSecret), n)
		require.Equal(t, patternWithMaskedSecret, bufioWriter.String(), "password should be scrubbed")
	})

	t.Run("handle writer error, all written", func(t *testing.T) {
		expectedError := fmt.Errorf("something went wrong")
		expectedData := make([]byte, MAX_WRITE_RETRIES-3)
		mockWriter := &mockWriter{
			Error: expectedError,
		}
		writer = NewScrubbingIoWriter(mockWriter, scrubDict)
		actualLength, actualError := writer.Write(expectedData)
		assert.NoError(t, actualError)
		assert.Equal(t, len(expectedData), actualLength)
	})

	t.Run("handle writer error, not all written", func(t *testing.T) {
		expectedError := fmt.Errorf("something went wrong")
		expectedData := make([]byte, MAX_WRITE_RETRIES*2)

		mockWriter := &mockWriter{
			Error:           expectedError,
			MaxBytesToWrite: 1, // expected data has more than 10 bytes, we have 10 retries, so one should be fine
		}
		writer = NewScrubbingIoWriter(mockWriter, scrubDict)
		actualLength, actualError := writer.Write(expectedData)
		assert.Error(t, actualError)
		assert.Equal(t, len(expectedData), actualLength)
	})
}

func TestScrubFunction(t *testing.T) {
	t.Run("scrub everything in dict", func(t *testing.T) {
		dict := ScrubbingDict{
			"secret":       {0, regexp.MustCompile("secret"), ""},
			"special":      {0, regexp.MustCompile("special"), ""},
			"be disclosed": {0, regexp.MustCompile("be disclosed"), ""},
		}
		input := "This is my secret message, which might not be special but definitely should not be disclosed."
		expected := "This is my *** message, which might not be *** but definitely should not ***."

		actual := scrub([]byte(input), dict, true)
		assert.Equal(t, expected, string(actual))
	})

	t.Run("scrub regex", func(t *testing.T) {
		input := "abc http://a:b@host.com asdf \nabc https://a:b@host.com asdf"
		expected := "abc http://***@host.com asdf \nabc https://***@host.com asdf"
		dict := addMandatoryMasking(ScrubbingDict{})

		actual := scrub([]byte(input), dict, true)
		assert.Equal(t, expected, string(actual))
	})

	t.Run("dont scrub urls without creds", func(t *testing.T) {
		input := "abc http://host.com asdf \nabc https://a:b@host.com asdf"
		expected := "abc http://host.com asdf \nabc https://***@host.com asdf"
		dict := addMandatoryMasking(ScrubbingDict{})

		actual := scrub([]byte(input), dict, true)
		assert.Equal(t, expected, string(actual))
	})
}

func TestScrub_MatchesPrivateScrubPath(t *testing.T) {
	dict := addMandatoryMasking(ScrubbingDict{})
	input := []byte("Authorization: Bearer sometoken123456")

	expected := scrub(input, dict, true)
	actual := Scrub(input, dict)

	assert.Equal(t, string(expected), string(actual))
	assert.Equal(t, "Authorization: Bearer ***", string(actual), "Scrub should redact the token, not just mirror the input")
}

func TestAddDefaults(t *testing.T) {
	dict := addMandatoryMasking(ScrubbingDict{})
	u, uErr := user.Current()
	assert.NoError(t, uErr)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "non-masked",
			input:    "asdf",
			expected: "asdf",
		},
		{
			name:     "http basic auth",
			input:    "http://a:b@host.com something else https://c:d@host.com asdf",
			expected: "http://***@host.com something else https://***@host.com asdf",
		},
		{
			name:     "token header with uuid",
			input:    "Token 01234567-0123-0123-0123-012345678901\" asdf",
			expected: "Token ***\" asdf",
		},
		{
			name:     "bearer header with uuid",
			input:    "bearer snyk_01234567-0123-0123-0123-012345678901.123\" asdf",
			expected: "bearer ***\" asdf",
		},
		{
			name:     "Token header with uuid",
			input:    "Token 01234567-0123-0123-0123-012345678901\" asdf",
			expected: "Token ***\" asdf",
		},
		{
			name:     "Basic header with value",
			input:    "basic dXM0000=\" asdf",
			expected: "basic ***\" asdf",
		},
		{
			name:     "Negotiate header with value",
			input:    "Proxy-Authorization: Negotiate YIICSAYGbWLumn6s9/8pfMB513heIeAJ/udlOk7K+XUbIoBZGzi0cA6xahe/vE0x2Fla0OeU+JK2h4G58i/lSVO0Ip+LDQApB+TC1SCh50KvgF1U8F/p4Pwr/LLrXX/pDgMUTt3kOmjRPJ9/qhU+aHrFWq3/L0E102+mc2bI asdf",
			expected: "Proxy-Authorization: Negotiate *** asdf",
		},
		{
			name:     "github pat (classic)",
			input:    "GITHUB_PRIVATE_TOKEN=ghp_012345678901234567890123456789012345",
			expected: "GITHUB_PRIVATE_TOKEN=ghp_***",
		},
		{
			name:     "github pat (fine-grained)",
			input:    "GITHUB_PRIVATE_TOKEN=github_pat_0123456789012345678901_01234567890123456789012345678901234567890123456789012345678",
			expected: "GITHUB_PRIVATE_TOKEN=github_pat_***",
		},
		{
			name:     "oauth access token",
			input:    "access_token=alittlesecret&expire",
			expected: "access_token=***&expire",
		},
		{
			name:     "oauth refresh token",
			input:    "refresh_token=alittlesecret&expire",
			expected: "refresh_token=***&expire",
		},
		{
			name:     "access token in json",
			input:    `{"access_token":"secret_access_token"}`,
			expected: `{"access_token":"***"}`,
		},
		{
			name:     "access token in json with multiple fields",
			input:    `{"unrelated":"foobar", "access_token":"secret_access_token","expires_in":300,"issued_at":"2025-06-20T15:32:38.38731422Z"}`,
			expected: `{"unrelated":"foobar", "access_token":"***","expires_in":300,"issued_at":"2025-06-20T15:32:38.38731422Z"}`,
		},
		{
			name:     "any type of token in json",
			input:    `{"something_token":"secret_access_token"}`,
			expected: `{"something_token":"***"}`,
		},
		{
			name:     "any type of token in json with postfix",
			input:    `{"something_token_and_a_postfix":"secret_access_token"}`,
			expected: `{"something_token_and_a_postfix":"***"}`,
		},
		{
			name:     "SNYK_TOKEN",
			input:    "SNYK_TOKEN=01234567-0123-0123-0123-012345678901",
			expected: "SNYK_TOKEN=***",
		},
		{
			name:     "username",
			input:    fmt.Sprintf("User %s.%s is repeatedly mentioned, but not partially.", u.Username, u.Username),
			expected: fmt.Sprintf("User %s.%s is repeatedly mentioned, but not partially.", SANITIZE_REPLACEMENT_STRING, SANITIZE_REPLACEMENT_STRING),
		},
		{
			name: "JSON-ish argument structure with verbatim output from snyk-config",
			input: `_: [
						'gcr.io/distroless/nodejs:latest',
						'john.doe',
						'hunter2',
						[other things]
				  	],`,
			expected: `_: [***],`,
		},
		{
			// A backslash-escaped bounding quote inside a dump value must not end the quoted
			// span early — otherwise a later `]` in the dump reads as its closing bracket.
			name:     "bracket dump with an escaped quote inside a quoted value",
			input:    `_: [ 'a\'b]c', 'd' ], next`,
			expected: `_: [***], next`,
		},
		{
			name: "username and password constellations passed in a JSON-ish structure with verbatim output from snyk-config",
			input: `{
				unrelated: dont-scrub,
				"unrelated": "dont-scrub",
				'unrelated': 'dont-scrub',
				unrelated: dont-scrub,
				'-p': 'hunter2',
				'u': 'john.doe',
				'p': 'hunter2',
				'p': 'hun"ter2',
				'p': 'hun ter2',
				'p': 'hun,ter2',
				"u": "john.doe",
				"u": "john'doe",
				"u": "john,doe",
				"u": "john doe",
				"p": "hunter2",
				u: 'john.doe',
				p: 'hunter2',
				"REGISTRY_USERNAME": "user",
				"REGISTRY_PASSWORD": "foobar",
				"MORE_UNRELATED": "DONT_SCRUB"
			}`,
			expected: `{
				unrelated: dont-scrub,
				"unrelated": "dont-scrub",
				'unrelated': 'dont-scrub',
				unrelated: dont-scrub,
				'-p': '***',
				'u': '***',
				'p': '***',
				'p': '***',
				'p': '***',
				'p': '***',
				"u": "***",
				"u": "***",
				"u": "***",
				"u": "***",
				"p": "***",
				u: '***',
				p: '***',
				"REGISTRY_USERNAME": "***",
				"REGISTRY_PASSWORD": "***",
				"MORE_UNRELATED": "DONT_SCRUB"
			}`,
		},
		{
			name:     "CLI arguments logged to the debug logs (same line, short-form, no equals signs)",
			input:    `container test gcr.io/distroless/nodejs:latest --platform=linux/arm64 --unrelated-argument --unrelated-argument-with-value "value" --unrelated-argument-with-equals-sign="value" -u john.doe -p hunter2 --log-level=trace`,
			expected: `container test gcr.io/distroless/nodejs:latest --platform=linux/arm64 --unrelated-argument --unrelated-argument-with-value "value" --unrelated-argument-with-equals-sign="value" -u *** -p *** --log-level=trace`,
		},
		{
			name:     "CLI arguments logged to the debug logs (same line, short-form, with equals signs)",
			input:    `container test gcr.io/distroless/nodejs:latest --platform=linux/arm64 --unrelated-argument --unrelated-argument-with-value "value" --unrelated-argument-with-equals-sign="value" -u=john.doe -p=hunter2 --log-level=trace`,
			expected: `container test gcr.io/distroless/nodejs:latest --platform=linux/arm64 --unrelated-argument --unrelated-argument-with-value "value" --unrelated-argument-with-equals-sign="value" -u=*** -p=*** --log-level=trace`,
		},
		{
			name:     "single-quoted key=value short form",
			input:    `before 'u=john.doe' 'p=hunter2' after`,
			expected: `before 'u=***' 'p=***' after`,
		},
		{
			// An escaped instance of the value's own bounding quote must not be read as the
			// value's closing delimiter.
			name:     "short-form single-quoted value containing an escaped apostrophe",
			input:    `'u': 'Nick\'s', 'other': 'keepme'`,
			expected: `'u': '***', 'other': 'keepme'`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := scrub([]byte(test.input), dict, true)
			assert.Equal(t, test.expected, string(actual))
		})
	}
}

// requireOnlyExpectedFieldsChanged decodes input and output as JSON objects and asserts that the
// only fields whose value differs are the ones named in changed. It is the structural half of the
// CLI-1732 regression tests: scrubbing has to redact the sensitive field and leave everything
// around it — other fields, and the JSON framing itself — exactly as it found it.
func requireOnlyExpectedFieldsChanged(t *testing.T, input, output string, changed map[string]any) {
	t.Helper()

	var before, after map[string]any
	require.NoError(t, json.Unmarshal([]byte(input), &before), "test input must be valid JSON to begin with")
	require.NoError(t, json.Unmarshal([]byte(output), &after),
		"scrubbed output must still be valid JSON, got: %s", output)
	require.Len(t, after, len(before), "scrubbing must not add or drop fields")

	for key, originalValue := range before {
		if expected, ok := changed[key]; ok {
			assert.Equal(t, expected, after[key], "field %q should have been redacted", key)
			continue
		}
		assert.Equal(t, originalValue, after[key], "field %q should have been left untouched", key)
	}
}

// TestScrub_RedactsOnlyTheMatchedSpan covers CLI-1732 bug A: scrub() used to look the captured
// value back up in the event and replace every occurrence of that text. A sensitive field whose
// value happens to be a JSON structural character (or any short string that recurs elsewhere)
// therefore blanked out unrelated parts of the event, up to and including the event's opening
// brace — which is what produced the customer's
// "zerolog: could not write event: cannot decode event: invalid character '*'".
func TestScrub_RedactsOnlyTheMatchedSpan(t *testing.T) {
	dict := addMandatoryMasking(ScrubbingDict{})

	tests := []struct {
		name     string
		input    string
		expected string
		changed  map[string]any
	}{
		{
			name:     "value is an opening brace that also opens the event",
			input:    `{"level":"debug","tokenHint":"{","message":"scanning"}`,
			expected: `{"level":"debug","tokenHint":"***","message":"scanning"}`,
			changed:  map[string]any{"tokenHint": SANITIZE_REPLACEMENT_STRING},
		},
		{
			name:     "value is a comma that also separates fields",
			input:    `{"level":"debug","userKind":",","message":"a,b,c"}`,
			expected: `{"level":"debug","userKind":"***","message":"a,b,c"}`,
			changed:  map[string]any{"userKind": SANITIZE_REPLACEMENT_STRING},
		},
		{
			name:     "value is a closing brace that also closes the event",
			input:    `{"level":"debug","tokenHint":"}","tail":"end"}`,
			expected: `{"level":"debug","tokenHint":"***","tail":"end"}`,
			changed:  map[string]any{"tokenHint": SANITIZE_REPLACEMENT_STRING},
		},
		{
			name:     "single character value that recurs in an unrelated field",
			input:    `{"level":"debug","apiKey":"a","path":"/a/b/a"}`,
			expected: `{"level":"debug","apiKey":"***","path":"/a/b/a"}`,
			changed:  map[string]any{"apiKey": SANITIZE_REPLACEMENT_STRING},
		},
		{
			name:     "value that also appears verbatim inside another field name",
			input:    `{"userName":"log","logLevel":"debug"}`,
			expected: `{"userName":"***","logLevel":"debug"}`,
			changed:  map[string]any{"userName": SANITIZE_REPLACEMENT_STRING},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := string(scrub([]byte(test.input), dict, true))

			assert.Equal(t, test.expected, actual)
			assert.True(t, json.Valid([]byte(actual)),
				"scrubbed output must remain decodable by zerolog, got: %s", actual)
			requireOnlyExpectedFieldsChanged(t, test.input, actual, test.changed)
		})
	}
}

// TestScrub_GreedyCapturesStopAtTheirOwnDelimiter covers CLI-1732 bug B: the `_: [...]` and the
// short-form `u`/`p` patterns captured with an unbounded greedy `.*`, so a match ran on to the
// last delimiter anywhere in the event and redacted every field in between.
func TestScrub_GreedyCapturesStopAtTheirOwnDelimiter(t *testing.T) {
	dict := addMandatoryMasking(ScrubbingDict{})

	tests := []struct {
		name     string
		input    string
		expected string
		changed  map[string]any
	}{
		{
			name:     "snyk-config bracket dump followed by more JSON",
			input:    `{"level":"debug","message":"_: [ 'test', 'monitor' ]","tags":["a","b"],"ok":true}`,
			expected: `{"level":"debug","message":"_: [***]","tags":["a","b"],"ok":true}`,
			changed:  map[string]any{"message": "_: [***]"},
		},
		{
			name:     "bracket dump with a nested bracket group is still redacted as a whole",
			input:    `{"message":"_: [ 'a', [nested], 'b' ]","after":"keepme"}`,
			expected: `{"message":"_: [***]","after":"keepme"}`,
			changed:  map[string]any{"message": "_: [***]"},
		},
		{
			name:     "short-form CLI arguments followed by more JSON",
			input:    `{"level":"debug","args":"-u john.doe -p hunter2","org":"acme","ok":true}`,
			expected: `{"level":"debug","args":"-u *** -p ***","org":"acme","ok":true}`,
			changed:  map[string]any{"args": "-u *** -p ***"},
		},
		{
			name:     "short-form quoted value followed by more JSON",
			input:    `{"u": "john.doe", "next": "keepme", "arr": [1,2]}`,
			expected: `{"u": "***", "next": "keepme", "arr": [1,2]}`,
			changed:  map[string]any{"u": SANITIZE_REPLACEMENT_STRING},
		},
		{
			// Bounding the value at `"` must not stop at a quote the value itself contains:
			// the escape belongs to the argument, so the whole secret still has to go.
			name:     "short-form argument value containing an escaped quote stays fully redacted",
			input:    `{"cfg":"-p hun\"ter2","next":"keepme"}`,
			expected: `{"cfg":"-p ***","next":"keepme"}`,
			changed:  map[string]any{"cfg": "-p ***"},
		},
		{
			// A `]` inside a quoted dump value used to read as the dump's own closing bracket,
			// truncating the capture and leaking the rest of the entry unredacted (see CLI-1732).
			name:     "bracket dump with a `]` inside a quoted value is still redacted as a whole",
			input:    `{"message":"_: [ 'a]b', 'c' ]","after":"keepme"}`,
			expected: `{"message":"_: [***]","after":"keepme"}`,
			changed:  map[string]any{"message": "_: [***]"},
		},
		{
			// Same as above for `[`: a quoted value containing an unmatched opening bracket must
			// not be read as the start of a new nested pair.
			name:     "bracket dump with a `[` inside a quoted value is still redacted as a whole",
			input:    `{"message":"_: [ 'a[b', 'c' ]","after":"keepme"}`,
			expected: `{"message":"_: [***]","after":"keepme"}`,
			changed:  map[string]any{"message": "_: [***]"},
		},
		{
			name:     "short-form value with no surrounding quotes at all",
			input:    `{"message":"u: john.doe, next: keepme"}`,
			expected: `{"message":"u: ***, next: keepme"}`,
			changed:  map[string]any{"message": "u: ***, next: keepme"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := string(scrub([]byte(test.input), dict, true))

			assert.Equal(t, test.expected, actual)
			assert.True(t, json.Valid([]byte(actual)),
				"scrubbed output must remain decodable by zerolog, got: %s", actual)
			requireOnlyExpectedFieldsChanged(t, test.input, actual, test.changed)
		})
	}
}

func TestScrubbingIoWriter_piecewise(t *testing.T) {
	scrubDict := map[string]scrubStruct{
		"token":    {0, regexp.MustCompile("token"), ""},
		"password": {0, regexp.MustCompile("password"), ""},
	}

	innerWriter := &mockWriter{
		MaxBytesToWrite: 16,
	}
	scrubbingWriter := NewScrubbingIoWriter(innerWriter, scrubDict)

	expectedOutput := []byte("this is a *** test and also a *** test")
	input := []byte("this is a token test and also a password test")
	n, err := scrubbingWriter.Write(input)
	assert.NoError(t, err)
	assert.Equal(t, len(input), n)
	t.Log(string(innerWriter.written))
	assert.Equal(t, string(expectedOutput), string(innerWriter.written))
}

func TestAddTermsToReplace(t *testing.T) {
	tests := []struct {
		name       string
		termsToAdd []string
		input      string
		expected   string
	}{
		{
			name:       "single term",
			termsToAdd: []string{"secret123"},
			input:      "This is my secret123 value",
			expected:   "This is my *** value",
		},
		{
			name:       "multiple terms",
			termsToAdd: []string{"password", "token", "key"},
			input:      "password is secret, token is hidden, key is protected",
			expected:   "*** is secret, *** is hidden, *** is protected",
		},
		{
			name:       "empty terms list",
			termsToAdd: []string{},
			input:      "nothing should be replaced here",
			expected:   "nothing should be replaced here",
		},
		{
			name:       "special characters in terms",
			termsToAdd: []string{"user@domain.com", "file.txt", "super=secret?password"},
			input:      "Email user@domain.com, file file.txt, and super=secret?password value",
			expected:   "Email ***, file ***, and *** value",
		},
		{
			name:       "terms with spaces",
			termsToAdd: []string{"secret phrase", "multi word key"},
			input:      "The secret phrase is hidden and multi word key is protected",
			expected:   "The *** is hidden and *** is protected",
		},
		{
			name:       "unicode characters",
			termsToAdd: []string{"café", "naïve"},
			input:      "The café is naïve about security",
			expected:   "The *** is *** about security",
		},
		{
			name:       "terms with newlines and tabs",
			termsToAdd: []string{"line1\nline2", "tab\tseparated"},
			input:      "First line1\nline2 then tab\tseparated values",
			expected:   "First *** then *** values",
		},
		{
			name:       "very long term",
			termsToAdd: []string{strings.Repeat("X", 1000)},
			input:      "Short text with " + strings.Repeat("X", 1000) + " long term",
			expected:   "Short text with *** long term",
		},
		{
			name:       "numeric terms",
			termsToAdd: []string{"12345", "987.654"},
			input:      "ID 12345 and value 987.654 are sensitive",
			expected:   "ID *** and value *** are sensitive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Run("IoWriter", func(t *testing.T) {
				mockWriter := &mockWriter{}
				writer := &scrubbingIoWriter{
					writer:    mockWriter,
					scrubDict: ScrubbingDict{},
				}

				writer.AddTermsToReplace(test.termsToAdd)

				n, err := writer.Write([]byte(test.input))
				assert.NoError(t, err)
				assert.Equal(t, len(test.input), n)
				assert.Equal(t, test.expected, string(mockWriter.written))
			})

			t.Run("LevelWriter", func(t *testing.T) {
				mockWriter := &mockWriter{}
				writer := &scrubbingLevelWriter{
					writer:    mockWriter,
					scrubDict: ScrubbingDict{},
				}

				writer.AddTermsToReplace(test.termsToAdd)

				n, err := writer.WriteLevel(zerolog.InfoLevel, []byte(test.input))
				assert.NoError(t, err)
				assert.Equal(t, len(test.input), n)
				assert.Equal(t, test.expected, string(mockWriter.written))
			})
		})
	}
}

func TestSnykPATScrubbing(t *testing.T) {
	dict := addMandatoryMasking(ScrubbingDict{})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Snyk PAT UAT token with Bearer",
			input:    "Authorization: Bearer snyk_uat.12345678.abcdefgh-ijklmnop.qrstuvwx-yz123456",
			expected: "Authorization: Bearer ***",
		},
		{
			name:     "Snyk PAT SAT token with Bearer",
			input:    "Authorization: Bearer snyk_sat.87654321.zyxwvuts-rqponmlk.jihgfedc-ba987654",
			expected: "Authorization: Bearer ***",
		},
		{
			name:     "Snyk PAT UAT token standalone",
			input:    "PAT_EU: snyk_uat.abcd1234.test-token-value.more-token-data",
			expected: "PAT_EU: snyk_uat.***",
		},
		{
			name:     "Snyk PAT SAT token standalone",
			input:    "Token: snyk_sat.12ab34cd.test_value-123.final_part-456",
			expected: "Token: snyk_sat.***",
		},
		{
			name:     "Snyk PAT token in environment variable",
			input:    "SNYK_TOKEN=snyk_uat.abcd1234.test-token-value.more-token-data",
			expected: "SNYK_TOKEN=***",
		},
		{
			name:     "Snyk PAT token in JSON",
			input:    `{"token":"snyk_sat.12ab34cd.test_value-123.final_part-456"}`,
			expected: `{"token":"***"}`,
		},
		{
			name:     "Multiple Snyk PAT tokens",
			input:    "First token: snyk_uat.11111111.first-token.part and second: snyk_sat.22222222.second-token.part",
			expected: "First token: ****** and second: snyk_sat.***",
		},
		{
			name:     "Snyk PAT token mixed with other tokens",
			input:    "Bearer token123 and snyk_uat.99999999.mixed-test.token-here and Basic auth456",
			expected: "Bearer *** and snyk_uat.*** and Basic ***",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := scrub([]byte(test.input), dict, true)
			assert.Equal(t, test.expected, string(actual))
		})
	}
}

func TestStaticTermReplacementPreservesJSONValidity(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "static term as bare JSON number value",
			input:    `{"level":"debug","count":12345,"message":"ok"}`,
			expected: `{"level":"debug","count":"***","message":"ok"}`,
		},
		{
			name:     "static term inside a quoted JSON string stays unquoted",
			input:    `{"message":"session id 12345 started"}`,
			expected: `{"message":"session id *** started"}`,
		},
		{
			name:     "static term as the entire quoted JSON string value",
			input:    `{"userId":"12345"}`,
			expected: `{"userId":"***"}`,
		},
		{
			name:     "static term as bare value at start of array",
			input:    `{"ids":[12345,67890]}`,
			expected: `{"ids":["***",67890]}`,
		},
		{
			name:     "static term fused to a decimal point is left alone",
			input:    `{"ratio":123.12345}`,
			expected: `{"ratio":123.12345}`,
		},
		{
			name:     "static term fused to a leading minus sign is left alone",
			input:    `{"delta":-12345}`,
			expected: `{"delta":-12345}`,
		},
		{
			name:     "digit-adjacent term inside a quoted string is still redacted",
			input:    `{"traceId":"1234598765"}`,
			expected: `{"traceId":"***98765"}`,
		},
		{
			name:     "pretty-printed JSON with spaces around colon and comma is still quoted",
			input:    `{"count" : 12345 , "ok" : true}`,
			expected: `{"count" : "***" , "ok" : true}`,
		},
		{
			name:     "whitespace run including a newline and a tab before the boundary is skipped",
			input:    "{\"count\":\n\t12345,\n\"ok\":true}",
			expected: "{\"count\":\n\t\"***\",\n\"ok\":true}",
		},
		{
			name:     "space before comma is tolerated",
			input:    `{"count":12345 ,"ok":true}`,
			expected: `{"count":"***" ,"ok":true}`,
		},
		{
			name:     "padded array brackets are tolerated",
			input:    `{"ids": [ 12345, 67890 ]}`,
			expected: `{"ids": [ "***", 67890 ]}`,
		},
		{
			// Whitespace-tolerant boundary detection could misread this prose's ": " and ", " as
			// bare-value boundaries -- the `quoted` guard in RedactStaticTerm must still keep it
			// from ever reaching isBareJSONValueSpan, since it's inside a quoted string value.
			name:     "term embedded in prose inside a quoted string is not misdetected as bare",
			input:    `{"msg":"reason: 12345, retry: token"}`,
			expected: `{"msg":"reason: ***, retry: token"}`,
		},
		{
			// Term sits after an escaped quote, with `:`/`,` neighbors — same shape as a bare
			// value. A tracker that toggles on escaped quotes too would misread this as
			// unquoted and inject stray quotes, corrupting the string.
			name:     "term downstream of an escaped quote in the same string stays unquoted",
			input:    `{"note":"a\"count:12345,done"}`,
			expected: `{"note":"a\"count:***,done"}`,
		},
		{
			// Second match must see the quote state left by the first (open string closed at
			// index 22): a regression that drops the carried `quoted` state between matches
			// would leave "count" wrongly treated as still-quoted and emit it unquoted.
			name:     "quote state threads correctly across two matches in one string",
			input:    `{"a":"has 12345 inside","b":12345}`,
			expected: `{"a":"has *** inside","b":"***"}`,
		},
		{
			// The escaped backslash right before the closing quote must consume its pair (\\),
			// not be mistaken for escaping that quote — otherwise the string never closes and
			// "count" gets wrongly left unquoted.
			name:     "term after a string ending in an escaped backslash is still recognized as bare",
			input:    `{"path":"C:\\","count":12345}`,
			expected: `{"path":"C:\\","count":"***"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			w := NewScrubbingIoWriter(&output, ScrubbingDict{})
			scrubbingWriter, ok := w.(ScrubbingLogWriter)
			require.True(t, ok)
			scrubbingWriter.AddTermsToReplace([]string{"12345"})

			_, err := w.Write([]byte(test.input))
			require.NoError(t, err)

			assert.True(t, json.Valid(output.Bytes()), "scrubbing produced invalid JSON: %s", output.Bytes())
			assert.Equal(t, test.expected, output.String())
		})
	}
}

// An empty term must not loop forever: strings.Index(s, "") matches at every position, so without
// this guard RedactStaticTerm would never advance past index 0. SanitizeUsername/SanitizeStaticValues
// call RedactStaticTerm per value with no empty-string filter, and an empty HomeDir/Username from
// os/user.Current() is a real input on some minimal environments.
func TestRedactStaticTerm_EmptyTermIsNoop(t *testing.T) {
	input := `{"count":12345}`
	done := make(chan string, 1)
	go func() { done <- RedactStaticTerm(input, "", "***") }()

	select {
	case actual := <-done:
		assert.Equal(t, input, actual)
	case <-time.After(time.Second):
		t.Fatal("RedactStaticTerm did not return for an empty term — possible infinite loop")
	}
}

// TestRedactStaticTerm pins the exported function's direct contract, including the start/end
// boundary case: a term with no boundary character on one side has nothing to confirm it's a
// bare value, so it's left unquoted rather than guessed at.
func TestRedactStaticTerm(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "bare value with both boundaries present is quoted",
			input:    `{"count":12345,"ok":true}`,
			expected: `{"count":"***","ok":true}`,
		},
		{
			name:     "term at start of s has no left boundary, left bare",
			input:    `12345,"b":2`,
			expected: `***,"b":2`,
		},
		{
			name:     "term at end of s has no right boundary, left bare",
			input:    `{"a":1,"b":12345`,
			expected: `{"a":1,"b":***`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, RedactStaticTerm(test.input, "12345", "***"))
		})
	}
}

// TestScrub_VsScrubValue contrasts the jsonAware split on identical input: Scrub quotes a bare
// match to keep JSON syntax valid, ScrubValue leaves it bare since there's no JSON to protect.
func TestScrub_VsScrubValue(t *testing.T) {
	dict := ScrubbingDict{}
	addStaticTermToDict("8080", dict)
	input := "port:8080,timeout:3000"

	assert.Equal(t, `port:"***",timeout:3000`, string(Scrub([]byte(input), dict)))
	assert.Equal(t, `port:***,timeout:3000`, string(ScrubValue([]byte(input), dict)))
}

// TestScrubValue covers non-JSON leaf values, e.g. AddExtension's pre-marshal string leaves.
// Scrub's JSON-value quoting and digit-fusion skip don't apply here — there's no JSON to protect.
func TestScrubValue(t *testing.T) {
	dict := ScrubbingDict{}
	addStaticTermToDict("8080", dict)
	addStaticTermToDict("12345", dict)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "term adjacent to colon and comma in freeform text is not quoted",
			input:    "port:8080,timeout:3000",
			expected: "port:***,timeout:3000",
		},
		{
			name:     "term fused to an adjacent digit in freeform text is still redacted",
			input:    "id: 123451234",
			expected: "id: ***1234",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := string(ScrubValue([]byte(test.input), dict))
			assert.Equal(t, test.expected, actual)
		})
	}
}
