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
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type mockWriter struct {
	written []byte
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	m.written = p
	return len(p), nil
}

func (m *mockWriter) WriteLevel(_ zerolog.Level, p []byte) (n int, err error) {
	m.written = p
	return len(p), nil
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
	s := []byte("password")

	config := configuration.NewInMemory()
	config.Set(configuration.AUTHENTICATION_TOKEN, "password")

	mockWriter := &mockWriter{}
	writer := NewScrubbingWriter(mockWriter, GetScrubDictFromConfig(config))

	n, err := writer.WriteLevel(zerolog.InfoLevel, s)
	assert.Nil(t, err)
	assert.Equal(t, len(s), n)

	require.Equal(t, "***", string(mockWriter.written), "password should be scrubbed")
}

func TestScrubbingIoWriter(t *testing.T) {
	scrubDict := map[string]bool{
		"token":    true,
		"password": true,
		"":         true,
	}

	pattern := "%s for my account, including my %s"
	patternWithSecret := fmt.Sprintf(pattern, "password", "token")
	patternWithMaskedSecret := fmt.Sprintf(pattern, redactMask, redactMask)

	bufioWriter := bytes.NewBufferString("")
	writer := NewScrubbingIoWriter(bufioWriter, scrubDict)

	// invoke method under test
	n, err := writer.Write([]byte(patternWithSecret))
	assert.Nil(t, err)
	assert.Equal(t, len(patternWithSecret), n)
	require.Equal(t, patternWithMaskedSecret, bufioWriter.String(), "password should be scrubbed")
}

func TestScrubFunction(t *testing.T) {
	t.Run("scrub everything in dict", func(t *testing.T) {
		dict := ScrubbingDict{"secret": true, "": true, "special": false, "be disclosed": true}
		input := "This is my secret message, which might not be special but definitely should not be disclosed."
		expected := "This is my *** message, which might not be *** but definitely should not ***."

		actual := scrub([]byte(input), compileRegularExpressions(dict))
		assert.Equal(t, expected, string(actual))
	})

	t.Run("scrub regex", func(t *testing.T) {
		input := "abc http://a:b@host.com asdf \nabc https://a:b@host.com asdf"
		expected := "abc http:***host.com asdf \nabc https:***host.com asdf"
		dict := addMandatoryMasking(ScrubbingDict{})

		actual := scrub([]byte(input), compileRegularExpressions(dict))
		assert.Equal(t, expected, string(actual))
	})

	t.Run("dont scrub urls without creds", func(t *testing.T) {
		input := "abc http://host.com asdf \nabc https://a:b@host.com asdf"
		expected := "abc http://host.com asdf \nabc https:***host.com asdf"
		dict := addMandatoryMasking(ScrubbingDict{})

		actual := scrub([]byte(input), compileRegularExpressions(dict))
		assert.Equal(t, expected, string(actual))
	})
}

func TestAddDefaults(t *testing.T) {
	dict := ScrubbingDict{}
	dict = addMandatoryMasking(dict)

	_, found := dict["//.*:.*@"]
	assert.True(t, found, "should mask http basic auth")
}
