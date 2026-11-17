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
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
)

func writeThroughScrubbingWriter(t *testing.T, config configuration.Configuration, event string) string {
	t.Helper()
	out := &bytes.Buffer{}
	writer := logging.NewScrubbingWriter(zerolog.MultiLevelWriter(out), logging.GetScrubDictFromConfig(config))
	_, err := writer.WriteLevel(zerolog.DebugLevel, []byte(event))
	require.NoError(t, err)
	return out.String()
}

func requireValidJSONObject(t *testing.T, scrubbed string) map[string]any {
	t.Helper()
	fields := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(scrubbed), &fields), "scrubbed event is not valid JSON: %s", scrubbed)
	return fields
}

func TestScrubbingWriter_RedactedEventsStayValidJSONWithoutTheSecret(t *testing.T) {
	tests := []struct {
		name         string
		event        string
		secretPieces []string
	}{
		{
			name:         "secret containing an escaped quote",
			event:        `{"level":"debug","token":"hunter\"twoSecret","message":"loaded credentials"}`,
			secretPieces: []string{"hunter", "twoSecret"},
		},
		{
			name:         "sensitive field with a number value",
			event:        `{"level":"debug","token":987654321,"message":"credentials refreshed"}`,
			secretPieces: []string{"987654321"},
		},
		{
			name:  "short-form credential field with a number value",
			event: `{"level":"debug","p":5,"message":"parsed short options"}`,
		},
		{
			name:  "short-form credential field with a bool value",
			event: `{"level":"debug","u":true,"message":"parsed short options"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scrubbed := writeThroughScrubbingWriter(t, configuration.NewWithOpts(), tt.event)

			fields := requireValidJSONObject(t, scrubbed)
			assert.NotEmpty(t, fields["message"])
			for _, piece := range tt.secretPieces {
				assert.NotContains(t, scrubbed, piece)
			}
		})
	}
}

func TestScrubbingWriter_NonSecretFieldsKeepTheirValues(t *testing.T) {
	redactionTerms := []string{"Content", "reference", "command"}
	tests := []struct {
		name      string
		terms     []string
		event     string
		preserved map[string]any
	}{
		{
			name:      "field containing an at sign after a URL field",
			event:     `{"level":"debug","url":"https://api.example.com:443/v1/x","email":"a@b.com","message":"sending request"}`,
			preserved: map[string]any{"url": "https://api.example.com:443/v1/x", "email": "a@b.com"},
		},
		{
			name:      "field name matching a redaction term",
			terms:     redactionTerms,
			event:     `{"level":"debug","command":"snyk test","message":"running"}`,
			preserved: map[string]any{"command": "snyk test"},
		},
		{
			name:      "field after arguments ending in a short flag",
			event:     `{"level":"debug","args":"snyk test -u","command":"monitor","message":"dispatching"}`,
			preserved: map[string]any{"args": "snyk test -u", "command": "monitor"},
		},
		{
			name:      "hyphenated word containing a redaction term",
			terms:     redactionTerms,
			event:     `{"level":"debug","message":"> Content-Type: application/json"}`,
			preserved: map[string]any{"message": "> Content-Type: application/json"},
		},
		{
			name:      "command line flag containing a redaction term",
			terms:     redactionTerms,
			event:     `{"level":"debug","message":"args: --target-reference=main"}`,
			preserved: map[string]any{"message": "args: --target-reference=main"},
		},
		{
			name:      "prose mentioning token or basic authentication",
			event:     `{"level":"debug","message":"Using token authentication and Basic authentication flow"}`,
			preserved: map[string]any{"message": "Using token authentication and Basic authentication flow"},
		},
		{
			name:      "lowercase word after token or bearer in prose",
			event:     `{"level":"debug","message":"refreshing the token because the server rejected the Bearer request"}`,
			preserved: map[string]any{"message": "refreshing the token because the server rejected the Bearer request"},
		},
		{
			name:      "URL followed by an email address in the same message",
			event:     `{"level":"debug","message":"cloning https://api.example.com:8443/org/repo for dev@example.com"}`,
			preserved: map[string]any{"message": "cloning https://api.example.com:8443/org/repo for dev@example.com"},
		},
		{
			name:      "short-form key next to another field in a non-JSON message",
			event:     `{"level":"debug","message":"fields \"u\",\"region\":\"eu\" loaded"}`,
			preserved: map[string]any{"message": `fields "u","region":"eu" loaded`},
		},
		{
			name:      "field names merely containing key or user",
			event:     `{"level":"debug","userAgent":"snyk-cli/1.0","cacheKey":"deps-lockfile","monkey":"banana","message":"cache lookup"}`,
			preserved: map[string]any{"userAgent": "snyk-cli/1.0", "cacheKey": "deps-lockfile", "monkey": "banana"},
		},
		{
			name:      "embedded JSON body with field names merely containing key or user",
			event:     `{"level":"debug","message":"< body: {\"cacheKey\":\"deps-lockfile\",\"userAgent\":\"snyk-cli/1.0\"}"}`,
			preserved: map[string]any{"message": `< body: {"cacheKey":"deps-lockfile","userAgent":"snyk-cli/1.0"}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scrubbed := writeThroughScrubbingWriter(t, configWithRedactionTerms(tt.terms...), tt.event)

			fields := requireValidJSONObject(t, scrubbed)
			for key, value := range tt.preserved {
				assert.Equal(t, value, fields[key], "field %q", key)
			}
		})
	}
}

func TestScrubbingWriter_SecretsAreStillRedacted(t *testing.T) {
	apiToken := fakeAPIToken()
	tokenConfig := configuration.NewWithOpts()
	tokenConfig.Set(configuration.AUTHENTICATION_TOKEN, apiToken)
	tokenWithTermsConfig := configWithRedactionTerms("Content", "reference", "command")
	tokenWithTermsConfig.Set(configuration.AUTHENTICATION_TOKEN, apiToken)
	before, after := fakeURLPasswordParts()
	atSignPasswordEvent := `{"level":"debug","message":"cloning https://someone:` + before + "@" + after + `@git.example.com/org/repo.git"}`

	tests := []struct {
		name   string
		config configuration.Configuration
		event  string
		secret string
	}{
		{
			name:   "value that is exactly a redaction term",
			config: configWithRedactionTerms("Content", "reference", "command"),
			event:  `{"level":"debug","value":"reference","message":"resolved the reference value"}`,
			secret: "reference",
		},
		{
			name:   "bearer token in an authorization header",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","message":"> Authorization: Bearer ` + fakeBearerToken() + `"}`,
			secret: fakeBearerToken(),
		},
		{
			name:   "credentials in a URL",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","message":"cloning https://someone:` + fakeURLPassword() + `@git.example.com/org/repo.git"}`,
			secret: fakeURLPassword(),
		},
		{
			name:   "JWT in an access token field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","access_token":"` + fakeJWT() + `","message":"received oauth response"}`,
			secret: "eyJ",
		},
		{
			name:   "GitHub personal access token",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","message":"using credential ` + fakeGitHubPAT() + `"}`,
			secret: fakeGitHubPATSuffix(),
		},
		{
			name:   "configured API token anywhere in the event",
			config: tokenConfig,
			event:  `{"level":"debug","env":"SNYK_CFG=` + apiToken + `","message":"authenticating with ` + apiToken + `"}`,
			secret: apiToken,
		},
		{
			name:   "configured API token joined to other text by a hyphen or dot",
			config: tokenWithTermsConfig,
			event:  `{"level":"debug","header":"prefix-` + apiToken + `","message":"cached under ` + apiToken + `.suffix"}`,
			secret: apiToken,
		},
		{
			name:   "short-form credentials containing a quote",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","message":"proxy login u: a\"b p: hun\"ter2 done"}`,
			secret: "ter2",
		},
		{
			name:   "password field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","password":"correct-horse-battery","message":"proxy configured"}`,
			secret: "correct-horse-battery",
		},
		{
			name:   "UUID-shaped token after token in prose",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","message":"using token ` + apiToken + ` for this request"}`,
			secret: apiToken,
		},
		{
			name:   "lowercase basic credential in an authorization header",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","message":"> Authorization: Basic ` + fakeLowercaseCredential() + `"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "URL password before an at sign inside it",
			config: configuration.NewWithOpts(),
			event:  atSignPasswordEvent,
			secret: before,
		},
		{
			name:   "URL password after an at sign inside it",
			config: configuration.NewWithOpts(),
			event:  atSignPasswordEvent,
			secret: after,
		},
		{
			name:   "apiKey field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","apiKey":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "x-api-key field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","x-api-key":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "client_secret field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","client_secret":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "userName field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","userName":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "Authorization field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","Authorization":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "Set-Cookie field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","Set-Cookie":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "secrets field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","secrets":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "tokens field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","tokens":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "passwords field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","passwords":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "cookies field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","cookies":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "apiKeys field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","apiKeys":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "api_keys field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","api_keys":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "authorizations field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","authorizations":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "REGISTRY_USERNAME field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","REGISTRY_USERNAME":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "PROXY_USER field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","PROXY_USER":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "registryUserName field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","registryUserName":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "proxy-user field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","proxy-user":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "requestHeaders field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","requestHeaders":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "response_headers field",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","response_headers":"` + fakeLowercaseCredential() + `","message":"request prepared"}`,
			secret: fakeLowercaseCredential(),
		},
		{
			name:   "password field inside an embedded JSON body",
			config: configuration.NewWithOpts(),
			event:  `{"level":"debug","message":"> body: {\"login\":\"someone\",\"password\":\"` + fakeLowercaseCredential() + `\"}"}`,
			secret: fakeLowercaseCredential(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scrubbed := writeThroughScrubbingWriter(t, tt.config, tt.event)

			requireValidJSONObject(t, scrubbed)
			assert.NotContains(t, scrubbed, tt.secret)
		})
	}
}
