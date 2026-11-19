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
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsSensitiveFieldName(t *testing.T) {
	sensitive := []string{
		"password", "apiKey", "x-api-key", "client_secret", "userName", "secrets", "tokens", "apikey", "accesskey",
		"authtoken", "clientsecret", "sessionKey", "passcode", "Authorization", "Set-Cookie", "cookies",
		"authorizations", "REGISTRY_USERNAME", "PROXY_USER", "requestHeaders", "response_headers", "privateKey",
		"fleetKey", "licenseKey", "ssh-key", "key", "u", "P", "login", "pwd", "passphrase", "client.secret",
		"Proxy-Authorization", "HTTP-HEADERS", "credentials", "keys",
	}
	notSensitive := []string{
		"userAgent", "cacheKey", "cacheKeys", "monkey", "monkeys", "keyboard", "userId", "userKind", "sortKey", "keyId",
		"apiKeyId", "tokenizer", "header", "headersCount", "loginUrl", "up", "command", "", "tokensFile", "ps", "us",
		// A hash of a password is not the password.
		"passwordHash",
	}
	for _, name := range sensitive {
		assert.True(t, IsSensitiveFieldName(name), name)
	}
	for _, name := range notSensitive {
		assert.False(t, IsSensitiveFieldName(name), name)
	}
}

func redactWithTerms(s string, terms ...string) string {
	set := map[string]struct{}{}
	for _, term := range terms {
		set[term] = struct{}{}
	}
	return newRules(map[string]struct{}{}, set).redact(s)
}

func TestRedact_TermsAreRedactedOnlyAsWholeTokens(t *testing.T) {
	tests := []struct {
		name, input, term, expected string
	}{
		{"whole input", "request", "request", "***"},
		{"inside a word", "requests and xrequest", "request", "requests and xrequest"},
		{"a rejected match does not hide a later one", "xrequest request", "request", "xrequest ***"},
		{"next to an underscore", "no_request_here", "request", "no_request_here"},
		{"joined by a hyphen", "Content-Type", "Content", "Content-Type"},
		{"joined by a dot", "request.id", "request", "request.id"},
		{"flag containing the term", "--target-reference=main", "reference", "--target-reference=main"},
		{"after a double hyphen", "wait--request", "request", "wait--***"},
		{"before a full stop", "the password is request.", "request", "the password is ***."},
		{"between slashes", "/a/request/b", "request", "/a/***/b"},
		{"between query separators", "?a=request&b=1", "request", "?a=***&b=1"},
		{"before a trailing hyphen", "request- next", "request", "***- next"},
		{"hyphenated term", "value a-b here", "a-b", "value *** here"},
		{"hyphenated term joined to a word", "xa-a-a", "a-a", "xa-a-a"},
		{"term with punctuation", "result: ok", "result:", "*** ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, redactWithTerms(tt.input, tt.term))
		})
	}
}

func TestRedact_LongerTermWinsOverItsPrefix(t *testing.T) {
	assert.Equal(t, "see ***", redactWithTerms("see internal-name", "internal", "internal-name"))
}

func TestRedact_SecretsMatchAnywhere(t *testing.T) {
	rules := newRules(map[string]struct{}{"s3cr3t": {}, "s3cr3t-and-more": {}}, map[string]struct{}{})

	assert.Equal(t, "x***y ***", rules.redact("xs3cr3ty s3cr3t-and-more"))
}

func TestRedact_StringRules(t *testing.T) {
	shaped := strings.Repeat("a1b2", 4)
	lowercase := strings.Repeat("qwerty", 3)
	digitFreeBase64 := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	uuid := strings.Join([]string{"5f3c9a2e", "8d41", "4b7a", "9c2e", "1f6d3b8a0e57"}, "-")
	pat := "snyk_uat." + strings.Repeat("a1", 4) + ".payload_part.sig-part"

	tests := []struct {
		name, input, expected string
	}{
		{"plain text", "asdf", "asdf"},

		{"URL userinfo", "http://a:b@host.com something else https://c:d@host.com asdf", "http://***@host.com something else https://***@host.com asdf"},
		{"URL followed by an email address", "cloning https://api.example.com:8443/org/repo for dev@example.com", "cloning https://api.example.com:8443/org/repo for dev@example.com"},
		{"at sign inside the URL password", "cloning https://a:b@c@host.com/org/repo", "cloning https://***@host.com/org/repo"},
		{"URL host with a port", "cloning https://a:b@host.com:8443/org/repo", "cloning https://***@host.com:8443/org/repo"},
		{"URL inside double quotes", `url="https://a:b@host.com/x" next="c@d.com"`, `url="https://***@host.com/x" next="c@d.com"`},
		{"URL inside single quotes followed by a quoted email", `url='https://host.com:8443/x', next='a:b@c.com'`, `url='https://host.com:8443/x', next='a:b@c.com'`},
		{"URL followed by whitespace and an at sign", "https://host.com:8443 a@b", "https://host.com:8443 a@b"},

		{"github classic token", "found ghp_" + strings.Repeat("0123456789", 4), "found ghp_***"},
		{"github fine-grained token", "found github_pat_" + strings.Repeat("0123456789", 2) + "_abcdefghij", "found github_pat_***"},
		{"snyk PAT", "found " + pat + " here", "found snyk_uat.*** here"},

		{"bearer in an authorization header", "Authorization: Bearer " + shaped, "Authorization: Bearer ***"},
		{"digit-free basic in an authorization header", "Authorization: Basic " + lowercase, "Authorization: Basic ***"},
		{"negotiate in a proxy authorization header", "Proxy-Authorization: Negotiate " + lowercase, "Proxy-Authorization: Negotiate ***"},
		{"token scheme in a lowercase header", "authorization: token " + lowercase, "authorization: token ***"},
		{"go-printed header map", "map[Accept:[application/json] Authorization:[Bearer " + lowercase + "]]", "map[Accept:[application/json] Authorization:[Bearer ***]]"},
		{"quoted header in embedded JSON", `{"Authorization": "Basic ` + lowercase + `"}`, `{"Authorization": "***"}`},
		{"credential-shaped bearer in prose", "retrying with Bearer " + shaped, "retrying with Bearer ***"},
		{"digit-free base64 basic in prose", "retrying with Basic " + digitFreeBase64, "retrying with Basic ***"},
		{"basic with base64 padding in prose", "retrying with Basic " + lowercase + "==", "retrying with Basic ***"},
		{"uuid after token in prose", "using token " + uuid + " now", "using token *** now"},
		{"token in prose before a quote", "Token " + uuid + `" asdf`, `Token ***" asdf`},
		{"credential after a repeated scheme word", "Bearer Bearer " + shaped, "Bearer Bearer ***"},
		{"credential after a repeated long scheme word", "Negotiate Negotiate " + shaped, "Negotiate Negotiate ***"},
		{"lowercase word after bearer in prose", "the Bearer request failed", "the Bearer request failed"},
		{"lowercase word after basic in prose", "Basic authentication flow", "Basic authentication flow"},
		{"lowercase word after negotiate in prose", "Negotiate handshake started", "Negotiate handshake started"},
		{"lowercase word after token in prose", "token because it expired", "token because it expired"},
		{"lowercase word after access_token in prose", "renewing access_token because it expired", "renewing access_token because it expired"},
		{"pipe before oken is not token", "a |oken " + shaped, "a |oken " + shaped},

		{"token followed by equals", "token=" + lowercase, "token=***"},
		{"token followed by colon", "token: " + lowercase, "token: ***"},
		{"access_token in a query", "access_token=" + lowercase + "&expire", "access_token=***&expire"},
		{"refresh_token followed by colon", "refresh_token: " + lowercase, "refresh_token: ***"},
		{"environment variable", "SNYK_TOKEN=" + uuid, "SNYK_TOKEN=***"},
		{"escaped JSON field in text", `{\"token\":\"` + lowercase + `\"}`, `{\"token\":\"***\"}`},
		{"JSON field with spaces and separators in its name", `{"Client.Secret" : "d4"}`, `{"Client.Secret" : "***"}`},
		{"sensitive field after a non-sensitive one", `{"cacheKey":"a1","apiKey":"b2"}`, `{"cacheKey":"a1","apiKey":"***"}`},
		{"non-sensitive field after a sensitive one", `{"API_KEY":"b2", "monkey":"c3"}`, `{"API_KEY":"***", "monkey":"c3"}`},
		{"embedded HTTP body", "< HTTP/1.1 200 OK\n< Content-Type: application/json\n\n{\"token\":\"abcdef123456\",\"expires_in\":3600}", "< HTTP/1.1 200 OK\n< Content-Type: application/json\n\n{\"token\":\"***\",\"expires_in\":3600}"},
		{"unclosed quoted value", `{"token":"abcdefgh`, `{"token":"***`},
		{"empty quoted value", `password=""`, `password=""`},
		{"pair nested in a value", `cfg="u: john"`, `cfg="u: ***"`},
		{"double-quoted key next to another field", `fields "u","region":"eu" loaded`, `fields "u","region":"eu" loaded`},
		{"single-quoted key next to another field", `fields 'p','host':'example.com' loaded`, `fields 'p','host':'example.com' loaded`},
		{"unquoted key followed by a comma", `keys u, region: eu`, `keys u, region: eu`},
		{"short key with a colon", `u: john.doe, region: eu`, `u: ***, region: eu`},
		{"escaped quote in a quoted value", `'u': 'Nick\'s', 'other': 'keepme'`, `'u': '***', 'other': 'keepme'`},
		{"single-quoted key=value", `before 'u=john.doe' 'p=hunter2' after`, `before 'u=***' 'p=***' after`},
		{"message that is a lone u", "u", "u"},
		{"message ending in p colon", "p:", "p:"},

		{"short flags", "-u john.doe -p hunter2 and more text", "-u *** -p *** and more text"},
		{"short flags with equals", "-u=john.doe -p=hunter2 --log-level=trace", "-u=*** -p=*** --log-level=trace"},
		{"long flags", "--username john --password=hunter2 --org=acme", "--username *** --password=*** --org=acme"},
		{"flag at the end", "flags -u 5 and -p", "flags -u *** and -p"},
		{"flag argument with an escaped quote", `-p hun\"ter2 next`, `-p *** next`},
		{
			"CLI arguments",
			`container test gcr.io/distroless/nodejs:latest --platform=linux/arm64 --unrelated-argument --unrelated-argument-with-value "value" --unrelated-argument-with-equals-sign="value" -u john.doe -p hunter2 --log-level=trace`,
			`container test gcr.io/distroless/nodejs:latest --platform=linux/arm64 --unrelated-argument --unrelated-argument-with-value "value" --unrelated-argument-with-equals-sign="value" -u *** -p *** --log-level=trace`,
		},
		{
			"JSON-ish configuration dump",
			`{
				unrelated: dont-scrub,
				"unrelated": "dont-scrub",
				'unrelated': 'dont-scrub',
				'-p': 'hunter2',
				'u': 'john.doe',
				'p': 'hun"ter2',
				'p': 'hun ter2',
				'p': 'hun,ter2',
				"u": "john'doe",
				"u": "john doe",
				u: 'john.doe',
				p: hunter2,
				"REGISTRY_USERNAME": "user",
				"REGISTRY_PASSWORD": "foobar",
				"MORE_UNRELATED": "DONT_SCRUB"
			}`,
			`{
				unrelated: dont-scrub,
				"unrelated": "dont-scrub",
				'unrelated': 'dont-scrub',
				'-p': '***',
				'u': '***',
				'p': '***',
				'p': '***',
				'p': '***',
				"u": "***",
				"u": "***",
				u: '***',
				p: ***,
				"REGISTRY_USERNAME": "***",
				"REGISTRY_PASSWORD": "***",
				"MORE_UNRELATED": "DONT_SCRUB"
			}`,
		},
	}
	rules := newRules(map[string]struct{}{}, map[string]struct{}{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, rules.redact(tt.input))
		})
	}
}

func TestLooksLikeCredential(t *testing.T) {
	for value, expected := range map[string]bool{
		"abcdef12":          true,
		"abcdefg=":          true,
		"abc+defg":          true,
		"abc/defg":          true,
		"abcdEfgh":          true,
		"abc1":              false,
		"authentication":    false,
		"Authentication":    false,
		"ABCDEFGH":          false,
		"snake_case-word.x": false,
	} {
		assert.Equal(t, expected, looksLikeCredential(value), value)
	}
}

func TestRedact_TakesLinearTime(t *testing.T) {
	rules := newRules(map[string]struct{}{"a-secret-value": {}}, map[string]struct{}{"token": {}})
	inputs := map[string]string{
		"auth scheme words":       strings.Repeat("token authentication ", 8000),
		"keys without separators": strings.Repeat("password ", 8000),
		"nested pairs":            strings.Repeat(`a="`, 8000),
		"unclosed sensitive keys": strings.Repeat(`"token":"`, 8000),
		"short flags":             strings.Repeat("-p ", 8000),
		"one long key":            strings.Repeat("k", 160000),
		"URL schemes":             strings.Repeat("https://", 8000),
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			rules.redact(input)
			// Linear work takes milliseconds; the bound leaves room for the race detector's slowdown.
			assert.Less(t, time.Since(start), 2*time.Second)
		})
	}
}
