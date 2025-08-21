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
	"os/user"
	"regexp"
	"strings"
	"testing"

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
			actual := scrub([]byte(test.input), dict)
			assert.Equal(t, test.expected, string(actual))
		})
	}
}
