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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
)

func TestRedactor_EachKindOfConfiguredSecretIsRedacted(t *testing.T) {
	fleetKey := base64.StdEncoding.EncodeToString([]byte("example-fleet-key-value"))
	const oauthToken = `{"access_token":"oauth-access-value-1","refresh_token":"oauth-refresh-value-2"}`

	tests := []struct {
		name   string
		key    string
		value  string
		secret string
	}{
		{"authentication token", configuration.AUTHENTICATION_TOKEN, "auth-token-value", "auth-token-value"},
		{"bearer token", configuration.AUTHENTICATION_BEARER_TOKEN, "bearer-value-1", "bearer-value-1"},
		{"client secret", auth.PARAMETER_CLIENT_SECRET, "client-secret-value", "client-secret-value"},
		{"client id", auth.PARAMETER_CLIENT_ID, "client-id-value", "client-id-value"},
		{"device token", machinecredential.CONFIG_KEY_DEVICE_TOKEN, "sdt_example-device-token-value", "sdt_example-device-token-value"},
		{"fleet key", machinecredential.CONFIG_KEY_FLEET_KEY, fleetKey, fleetKey},
		{"oauth access token", auth.CONFIG_KEY_OAUTH_TOKEN, oauthToken, "oauth-access-value-1"},
		{"oauth refresh token", auth.CONFIG_KEY_OAUTH_TOKEN, oauthToken, "oauth-refresh-value-2"},
		{"special characters", configuration.AUTHENTICATION_TOKEN, "a.b+c(d)[e]*?$^|{1}", "a.b+c(d)[e]*?$^|{1}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configuration.NewInMemory()
			config.Set(tt.key, tt.value)

			redacted := logging.NewRedactor(func() configuration.Configuration { return config }).Redact("seen " + tt.secret + " here")

			assert.Equal(t, "seen *** here", redacted)
		})
	}
}

func TestRedactor_RedactsTheConfiguredTokenAndTermsInText(t *testing.T) {
	longTerm := strings.Repeat("X", 1000)
	tests := []struct {
		name     string
		token    string
		terms    []string
		input    string
		expected string
	}{
		{"term before a comma", "", []string{"12345"}, "count:12345, retrying", "count:***, retrying"},
		{"several terms", "", []string{"token", "secret"}, "secret for my account, including my token", "*** for my account, including my ***"},
		{"term of several words", "", []string{"secret", "special", "be disclosed"}, "This is my secret message, which might not be special but definitely should not be disclosed.", "This is my *** message, which might not be *** but definitely should not ***."},
		{"terms between words", "", []string{"token", "password"}, "this is a token test and also a password test", "this is a *** test and also a *** test"},
		{"single term", "", []string{"secret123"}, "This is my secret123 value", "This is my *** value"},
		{"terms at the start of clauses", "", []string{"password", "token", "key"}, "password is secret, token is hidden, key is protected", "*** is secret, *** is hidden, *** is protected"},
		{"no terms", "", nil, "nothing should be replaced here", "nothing should be replaced here"},
		{"terms with special characters", "", []string{"user@domain.com", "file.txt", "super=secret?password"}, "Email user@domain.com, file file.txt, and super=secret?password value", "Email ***, file ***, and *** value"},
		{"terms with spaces", "", []string{"secret phrase", "multi word key"}, "The secret phrase is hidden and multi word key is protected", "The *** is hidden and *** is protected"},
		{"terms with non-ASCII letters", "", []string{"café", "naïve"}, "The café is naïve about security", "The *** is *** about security"},
		{"terms with a newline and a tab", "", []string{"line1\nline2", "tab\tseparated"}, "First line1\nline2 then tab\tseparated values", "First *** then *** values"},
		{"very long term", "", []string{longTerm}, "Short text with " + longTerm + " long term", "Short text with *** long term"},
		{"numeric terms", "", []string{"12345", "987.654"}, "ID 12345 and value 987.654 are sensitive", "ID *** and value *** are sensitive"},
		{"empty term", "", []string{""}, "request", "request"},
		{"empty token and empty term", "", []string{""}, `{"count":12345}`, `{"count":12345}`},
		{"token inside a number", "12345", nil, "id: 123451234", "id: ***1234"},
		{"token as a JSON number", "12345", nil, `{"count":12345,"ok":true}`, `{"count":***,"ok":true}`},
		{"token at the start", "12345", nil, `12345,"b":2`, `***,"b":2`},
		{"token at the end", "12345", nil, `{"a":1,"b":12345`, `{"a":1,"b":***`},
		{"token that is all of the text", "12345", nil, "12345", "***"},
		{"token next to another number", "8080", nil, `{"port":8080,"timeout":3000}`, `{"port":***,"timeout":3000}`},
		{"token in a colon list", "8080", nil, "port:8080,timeout:3000", "port:***,timeout:3000"},
		{"token containing a term", "abc-secret-xyz", []string{"secret"}, "abc-secret-xyz", "***"},
		{"token that is also a term", "shared", []string{"shared"}, "xsharedy", "x***y"},
		{"token before a newline", "io-writer-token-value", nil, "seen io-writer-token-value here\n", "seen *** here\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configuration.NewInMemory()
			config.Set(configuration.AUTHENTICATION_TOKEN, tt.token)
			config.Set(logging.REDACTION_TERMS, tt.terms)

			redacted := logging.NewRedactor(func() configuration.Configuration { return config }).Redact(tt.input)

			assert.Equal(t, tt.expected, redacted)
		})
	}
}

func TestRedactor_EveryLineOfAConfiguredMachineCredentialIsRedacted(t *testing.T) {
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	keyPEM, err := machineenrollment.EncodeKeyPEM(key)
	require.NoError(t, err)
	storedJSON, err := json.Marshal(map[string]string{"client_id": "machine-client-id", "private_key_pem": string(keyPEM)})
	require.NoError(t, err)
	config := configuration.NewInMemory()
	config.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, string(storedJSON))
	redactor := logging.NewRedactor(func() configuration.Configuration { return config })

	for _, line := range pemBodyLines(t, keyPEM) {
		assert.Equal(t, "seen *** here", redactor.Redact("seen "+line+" here"))
	}
}

func pemBodyLines(t *testing.T, keyPEM []byte) []string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(keyPEM)), "\n")
	require.Greater(t, len(lines), 3, "the PEM has several body lines")
	return lines[1 : len(lines)-1]
}

func TestRedactor_MachineCredentialIsRedactedInEveryShape(t *testing.T) {
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	keyPEM, err := machineenrollment.EncodeKeyPEM(key)
	require.NoError(t, err)
	storedJSON, err := json.Marshal(map[string]string{"client_id": "machine-client-id", "private_key_pem": string(keyPEM)})
	require.NoError(t, err)
	config := configuration.NewInMemory()
	config.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, string(storedJSON))
	bodyLines := pemBodyLines(t, keyPEM)
	redactor := logging.NewRedactor(func() configuration.Configuration { return config })

	for name, line := range map[string]string{
		"pem as is":        "pem: " + string(keyPEM),
		"stored value":     "value: " + string(storedJSON),
		"pem lines":        "lines: " + strings.Join(bodyLines, " "),
		"escaped newlines": "value: " + strings.ReplaceAll(string(keyPEM), "\n", `\n`),
	} {
		t.Run(name, func(t *testing.T) {
			redacted := redactor.Redact(line)
			for _, bodyLine := range bodyLines {
				assert.NotContains(t, redacted, bodyLine)
			}
		})
	}
	assert.Equal(t, "client: machine-client-id", redactor.Redact("client: machine-client-id"))
}

func TestRedactor_ShortDeviceTokenAndFleetKeyAreNotSecrets(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(machinecredential.CONFIG_KEY_DEVICE_TOKEN, "short-token")
	config.Set(machinecredential.CONFIG_KEY_FLEET_KEY, "short-key")

	assert.Equal(t, "short-token short-key", logging.NewRedactor(func() configuration.Configuration { return config }).Redact("short-token short-key"))
}

func TestRedactor_ReadsTheConfigurationOnEveryRedaction(t *testing.T) {
	config := configuration.NewInMemory()
	redactor := logging.NewRedactor(func() configuration.Configuration { return config })
	require.Equal(t, "first-token-value", redactor.Redact("first-token-value"))

	config.Set(configuration.AUTHENTICATION_TOKEN, "first-token-value")
	assert.Equal(t, "***", redactor.Redact("first-token-value"))

	config.Set(configuration.AUTHENTICATION_TOKEN, "second-token-value")
	assert.Equal(t, "*** ***", redactor.Redact("first-token-value second-token-value"), "a rotated token stays redacted")

	config.Set(logging.REDACTION_TERMS, []string{"internal-name"})
	assert.Equal(t, "see ***", redactor.Redact("see internal-name"))
}

func TestRedactor_KeepsRedactingKnownSecretsWhileTheProviderReturnsNoConfiguration(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(configuration.AUTHENTICATION_TOKEN, "known-token-value")
	redactor := logging.NewRedactor(func() configuration.Configuration { return config })
	require.Equal(t, "***", redactor.Redact("known-token-value"))

	config = nil

	assert.Equal(t, "*** password=***", redactor.Redact("known-token-value password=hunter22"))
}

func TestRedactor_TokenFromAnEnvironmentVariableIsRedacted(t *testing.T) {
	t.Setenv("EXAMPLE_TOKEN", "env-token-value-1")
	config := configuration.NewWithOpts(configuration.WithSupportedEnvVars("EXAMPLE_TOKEN"))
	config.AddAlternativeKeys(configuration.AUTHENTICATION_TOKEN, []string{"example_token"})

	assert.Equal(t, "using ***", logging.NewRedactor(func() configuration.Configuration { return config }).Redact("using env-token-value-1"))
}

func TestRedactor_ConcurrentRedactionsWhileTheTokenRotates(t *testing.T) {
	config := configuration.NewInMemory()
	redactor := logging.NewRedactor(func() configuration.Configuration { return config })
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				redactor.Redact("some text")
			}
		})
	}
	wg.Go(func() {
		for i := range 8 {
			config.Set(configuration.AUTHENTICATION_TOKEN, fmt.Sprintf("rotated-token-%d", i))
		}
	})
	wg.Wait()

	assert.Equal(t, "***", redactor.Redact("rotated-token-7"))
}

func TestRedactor_RedactionDuringAnotherRedactionsConfigurationReadSeesTheCurrentToken(t *testing.T) {
	config := configuration.NewInMemory()
	firstReadStarted, releaseFirstRead := blockFirstReadOfRedactionTerms(t, config)
	redactor := logging.NewRedactor(func() configuration.Configuration { return config })
	firstRedactionDone := make(chan struct{})
	go func() {
		defer close(firstRedactionDone)
		redactor.Redact("first")
	}()
	waitFor(t, firstReadStarted, "the first redaction to read the configuration")

	config.Set(configuration.AUTHENTICATION_TOKEN, "set-during-read-1")
	redacted := redactor.Redact("using set-during-read-1")
	releaseFirstRead()
	waitFor(t, firstRedactionDone, "the first redaction to finish")

	assert.Equal(t, "using ***", redacted)
	assert.Equal(t, "still using ***", redactor.Redact("still using set-during-read-1"), "the blocked read does not undo the newer token")
}

func TestRedactor_SnapshotReadsTheConfigurationOnceForEveryStringItRedacts(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(configuration.AUTHENTICATION_TOKEN, "snapshot-token-1")
	var reads atomic.Int32
	config.AddDefaultValue(logging.REDACTION_TERMS, func(_ configuration.Configuration, existing interface{}) (interface{}, error) {
		reads.Add(1)
		return existing, nil
	})
	redact := logging.NewRedactor(func() configuration.Configuration { return config }).Snapshot()

	for i := range 10 {
		assert.Equal(t, fmt.Sprintf("leaf %d ***", i), redact(fmt.Sprintf("leaf %d snapshot-token-1", i)))
	}
	assert.Equal(t, int32(1), reads.Load())
}
