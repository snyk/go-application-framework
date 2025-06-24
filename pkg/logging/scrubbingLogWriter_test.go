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
	"fmt"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"
	"os/user"
	"regexp"
	"testing"

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

func TestScrubbingIoWriter(t *testing.T) {
	scrubDict := map[string]scrubStruct{
		"token":  {0, regexp.MustCompile("token")},
		"secret": {0, regexp.MustCompile("secret")},
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

		writer.(ScrubbingLogWriter).RemoveTerm("token")
		writer.(ScrubbingLogWriter).RemoveTerm("secret")

		n, err = writer.Write([]byte(patternWithSecret))
		require.NoError(t, err)
		require.Equal(t, len(patternWithSecret), n)
		require.Equal(t, patternWithSecret, bufioWriter.String())
	})

	// now re-add
	t.Run("now re-add", func(t *testing.T) {
		bufioWriter = bytes.NewBufferString("")
		writer = NewScrubbingIoWriter(bufioWriter, scrubDict)
		writer.(ScrubbingLogWriter).AddTerm("token", 0)
		writer.(ScrubbingLogWriter).AddTerm("secret", 0)

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
			"secret":       {0, regexp.MustCompile("secret")},
			"special":      {0, regexp.MustCompile("special")},
			"be disclosed": {0, regexp.MustCompile("be disclosed")},
		}
		input := "This is my secret message, which might not be special but definitely should not be disclosed."
		expected := "This is my *** message, which might not be *** but definitely should not ***."

		actual := scrub([]byte(input), dict)
		assert.Equal(t, expected, string(actual))
	})

	t.Run("scrub regex", func(t *testing.T) {
		input := "abc http://a:b@host.com asdf \nabc https://a:b@host.com asdf"
		expected := "abc http://***@host.com asdf \nabc https://***@host.com asdf"
		dict := addMandatoryMasking(ScrubbingDict{})

		actual := scrub([]byte(input), dict)
		assert.Equal(t, expected, string(actual))
	})

	t.Run("dont scrub urls without creds", func(t *testing.T) {
		input := "abc http://host.com asdf \nabc https://a:b@host.com asdf"
		expected := "abc http://host.com asdf \nabc https://***@host.com asdf"
		dict := addMandatoryMasking(ScrubbingDict{})

		actual := scrub([]byte(input), dict)
		assert.Equal(t, expected, string(actual))
	})
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
			name: "cli argument mapping from snyk-config debug logging",
			input: `{
				username: 'username-set',
				'username=john.doe': true,
				password: 'password-set',
				'password=foobar': true,
				'u=foobar': true,
				'password-with-double-quotes=foo"bar': true,
				"password-with-single-quotes=foo'bar": true,
				'password-with-comma=foo,bar': true,
				'my-password-with-spaces=foo bar': true,
				'my-password-thats-solid=solid': true,
				'p=foobar': true,
				debug: true,
				'log-level': 'trace'
			}`,
			expected: `{
				username: 'username-set',
				'username=***': true,
				password: 'password-set',
				'password=***': true,
				'u=***': true,
				'password-with-double-quotes=***': true,
				"password-with-single-quotes=***": true,
				'password-with-comma=***': true,
				'my-password-with-spaces=***': true,
				'my-password-thats-***=***': true,
				'p=***': true,
				debug: true,
				'log-level': 'trace'
			}`,
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
			name: "CLI arguments logged to the debug logs (multi-line)",
			input: `Arguments:[
			container test gcr.io/distroless/nodejs:latest
			--platform=linux/arm64
			--unrelated-argument
			--unrelated-argument-with-value "value"
			--unrelated-argument-with-equals-sign="value"
			-u john.doe
			-p hunter2
			--username john.doe
			--password hunter2
			--a-password-with-secret-in-the-value 'super-secret-password'
			--a-password-with-an-equals-sign='hunter2'
			--a-password-with-spaces='hun ter2'
			--a-password-with-double-quotes='hun"ter2'
			--a-password-with-single-quotes="hun'ter2"
			--token "token"
			--password-with-no-value
			--another-unrelated-at-the-end
			--log-level=trace
			-d
			--debug
		]`,
			expected: `Arguments:[
			container test gcr.io/distroless/nodejs:latest
			--platform=linux/arm64
			--unrelated-argument
			--unrelated-argument-with-value "value"
			--unrelated-argument-with-equals-sign="value"
			-u ***
			-p ***
			--username ***
			--password ***
			--a-password-with-secret-in-the-value '***
			--a-password-with-an-equals-sign=***
			--a-password-with-spaces=***
			--a-password-with-double-quotes=***
			--a-password-with-single-quotes=***
			--token "***
			--password-with-no-value
			--another-unrelated-at-the-end
			--log-level=trace
			-d
			--debug
		]`,
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
			name:     "CLI arguments logged to the debug logs (same line, long-form, no equals signs)",
			input:    `container test ubuntu:latest --username john.doe --password solidpassword -d`,
			expected: `container test ubuntu:latest --username *** --password *** -d`,
		},
		{
			name:     "CLI arguments logged to the debug logs (same line, long-form, with equals signs)",
			input:    `container test ubuntu:latest --username=john.doe --password=solidpassword -d`,
			expected: `container test ubuntu:latest --username=*** --password=*** -d`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := scrub([]byte(test.input), dict)
			assert.Equal(t, test.expected, string(actual))
		})
	}
}

func TestScrubbingIoWriter_piecewise(t *testing.T) {
	scrubDict := map[string]scrubStruct{
		"token":    {0, regexp.MustCompile("token")},
		"password": {0, regexp.MustCompile("password")},
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
