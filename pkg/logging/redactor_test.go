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
	tests := []struct {
		name      string
		sensitive bool
	}{
		{"password", true},
		{"proxyPassword", true},
		{"REGISTRY_PASSWORD", true},
		{"passwd", true},
		{"passwort", true},
		{"passcode", true},
		{"passphrase", true},
		{"pwd", true},
		{"passwordHash", true},
		{"passwordPlain", true},
		{"passwords", true},
		{"secret", true},
		{"secrets", true},
		{"secretValue", true},
		{"client_secret", true},
		{"client.secret", true},
		{"clientsecret", true},
		{"token", true},
		{"tokens", true},
		{"tokenValue", true},
		{"tokensFile", true},
		{"tokenHint", true},
		{"access_token", true},
		{"refreshToken", true},
		{"oauth2Token", true},
		{"authtoken", true},
		{"credential", true},
		{"credentials", true},
		{"awsCredentials", true},
		{"authorization", true},
		{"Authorization", true},
		{"authorizations", true},
		{"proxy-authorization", true},
		{"Proxy-Authorization", true},
		{"cookie", true},
		{"cookies", true},
		{"Set-Cookie", true},
		{"key", true},
		{"KEY", true},
		{"keys", true},
		{"apiKey", true},
		{"apikey", true},
		{"APIKey", true},
		{"API_KEY", true},
		{"x-api-key", true},
		{"apiKeyValue", true},
		{"apiKeyId", true},
		{"accesskey", true},
		{"access_key", true},
		{"secretKey", true},
		{"sessionKey", true},
		{"privateKey", true},
		{"privateKeyPem", true},
		{"encryptionKey", true},
		{"signingKey", true},
		{"clientKey", true},
		{"fleetKey", true},
		{"licenseKey", true},
		{"ssh-key", true},
		{"headers", true},
		{"Headers", true},
		{"requestHeaders", true},
		{"response_headers", true},
		{"HTTP-HEADERS", true},
		{"user", true},
		{"USER", true},
		{"username", true},
		{"userName", true},
		{"user_name", true},
		{"nameUser", true},
		{"REGISTRY_USERNAME", true},
		{"registry_user_name", true},
		{"PROXY_USER", true},
		{"login", true},
		{"u", true},
		{"P", true},

		{"cacheKey", false},
		{"cacheKeys", false},
		{"keyId", false},
		{"sortKey", false},
		{"monkey", false},
		{"monkeys", false},
		{"keyboard", false},
		{"userAgent", false},
		{"userId", false},
		{"userID", false},
		{"userKind", false},
		{"userNameHint", false},
		{"tokenizer", false},
		{"secretss", false},
		{"header", false},
		{"headersCount", false},
		{"loginUrl", false},
		{"up", false},
		{"command", false},
		{"ps", false},
		{"us", false},
		{"", false},
		{"  ", false},
		{"_-.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.sensitive, IsSensitiveFieldName(tt.name))
		})
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
		{"at the start", "request pending", "request", "*** pending"},
		{"at the end", "pending request", "request", "pending ***"},
		{"before an exclamation mark", "request!", "request", "***!"},
		{"between digits", "id: 123451234", "12345", "id: 123451234"},
		{"no occurrence", "nothing here", "request", "nothing here"},
		{"empty input", "", "request", ""},
		{"after a non-ASCII letter", "préquest", "quest", "préquest"},
		{"before a non-ASCII digit", "request١", "request", "request١"},
		{"joined by a hyphen to a non-ASCII letter", "é-request", "request", "é-request"},
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
	patOfKind := func(kind, id string) string {
		return "snyk_" + kind + "." + strings.Repeat(id, 8) + ".abcdefgh-ijklmnop.qrstuvwx-yz123456"
	}
	uuidZeros := strings.Join([]string{"01234567", "0123", "0123", "0123", "012345678901"}, "-")

	tests := []struct {
		name, input, expected string
	}{
		{"plain text", "asdf", "asdf"},

		{"URL without userinfo next to one with it", "abc http://host.com asdf \nabc https://a:b@host.com asdf", "abc http://host.com asdf \nabc https://***@host.com asdf"},
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
		{"snyk PAT after bearer in a header", "Authorization: Bearer " + pat, "Authorization: Bearer ***"},
		{"snyk user PAT after bearer in a header", "Authorization: Bearer " + patOfKind("uat", "1"), "Authorization: Bearer ***"},
		{"snyk service PAT after bearer in a header", "Authorization: Bearer " + patOfKind("sat", "8"), "Authorization: Bearer ***"},
		{"snyk PAT after a token key", "Token: " + patOfKind("sat", "2"), "Token: ***"},
		{"snyk PAT in an environment variable", "SNYK_TOKEN=" + patOfKind("uat", "3"), "SNYK_TOKEN=***"},
		{"snyk PAT in a JSON token field", `{"token":"` + patOfKind("sat", "4") + `"}`, `{"token":"***"}`},
		{"several snyk PATs", "First token: " + patOfKind("uat", "5") + " and second: " + patOfKind("sat", "6"), "First token: *** and second: snyk_sat.***"},
		{"snyk PAT next to auth-scheme credentials", "Bearer token123 and " + patOfKind("uat", "9") + " and Basic auth456", "Bearer *** and snyk_uat.*** and Basic ***"},

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
		{"lowercase bearer before a quote", "bearer snyk_" + uuidZeros + `.123" asdf`, `bearer ***" asdf`},
		{"lowercase basic before a quote", `basic dXM0000=" asdf`, `basic ***" asdf`},
		{"lowercase word after bearer in prose is not a credential", "retrying with Bearer authentication", "retrying with Bearer authentication"},
		{"capitalised word after bearer in prose is not a credential", "retrying with Bearer Authentication", "retrying with Bearer Authentication"},
		{"uppercase word after bearer in prose is not a credential", "retrying with Bearer ABCDEF", "retrying with Bearer ABCDEF"},
		{"identifier after bearer in prose is not a credential", "retrying with Bearer snake_case-word.x", "retrying with Bearer snake_case-word.x"},
		{"bearer in a JSON string", `"Bearer abcdefghij1"`, `"Bearer ***"`},
		{"credential after a repeated scheme word", "Bearer Bearer " + shaped, "Bearer Bearer ***"},
		{"credential after a repeated long scheme word", "Negotiate Negotiate " + shaped, "Negotiate Negotiate ***"},
		{"lowercase word after bearer in prose", "the Bearer request failed", "the Bearer request failed"},
		{"lowercase word after basic in prose", "Basic authentication flow", "Basic authentication flow"},
		{"lowercase word after negotiate in prose", "Negotiate handshake started", "Negotiate handshake started"},
		{"lowercase word after token in prose", "token because it expired", "token because it expired"},
		{"lowercase word after access_token in prose", "renewing access_token because it expired", "renewing access_token because it expired"},
		{"pipe before oken is not token", "a |oken " + shaped, "a |oken " + shaped},
		{"pipe before earer is not bearer", "a |earer " + shaped, "a |earer " + shaped},
		{"pipe before asic is not basic", "a |asic " + shaped, "a |asic " + shaped},
		{"pipe before egotiate is not negotiate", "a |egotiate " + shaped, "a |egotiate " + shaped},
		{"short credential after bearer in prose", "retrying with Bearer abcdef1", "retrying with Bearer ***"},
		{"short credential after basic in prose", "a token and Basic auth456", "a token and Basic ***"},
		{"short credential after token in prose", "retrying with token abc123x", "retrying with token ***"},
		{"credential in prose stops at markup", `<a href="x">Bearer abcdefghij1</a>`, `<a href="x">Bearer ***</a>`},
		{"credential in a header stops at markup", "<b>Authorization: Bearer abcdefghij1</b>", "<b>Authorization: Bearer ***</b>"},

		{"token followed by equals", "token=" + lowercase, "token=***"},
		{"token followed by colon", "token: " + lowercase, "token: ***"},
		{"access_token in a query", "access_token=" + lowercase + "&expire", "access_token=***&expire"},
		{"refresh_token in a query", "refresh_token=" + lowercase + "&expire", "refresh_token=***&expire"},
		{"access_token in JSON", `{"access_token":"secret_access_token"}`, `{"access_token":"***"}`},
		{"access_token among other JSON fields", `{"unrelated":"foobar", "access_token":"secret_access_token","expires_in":300,"issued_at":"2025-06-20T15:32:38.38731422Z"}`, `{"unrelated":"foobar", "access_token":"***","expires_in":300,"issued_at":"2025-06-20T15:32:38.38731422Z"}`},
		{"field ending in token in JSON", `{"something_token":"secret_access_token"}`, `{"something_token":"***"}`},
		{"field containing the word token in JSON", `{"something_token_and_a_postfix":"secret_access_token"}`, `{"something_token_and_a_postfix":"***"}`},
		{"refresh_token followed by colon", "refresh_token: " + lowercase, "refresh_token: ***"},
		{"environment variable", "SNYK_TOKEN=" + uuid, "SNYK_TOKEN=***"},
		{"escaped JSON field in text", `{\"token\":\"` + lowercase + `\"}`, `{\"token\":\"***\"}`},
		{"JSON field with spaces and separators in its name", `{"Client.Secret" : "d4"}`, `{"Client.Secret" : "***"}`},
		{"sensitive field after a non-sensitive one", `{"cacheKey":"a1","apiKey":"b2"}`, `{"cacheKey":"a1","apiKey":"***"}`},
		{"non-sensitive field after a sensitive one", `{"API_KEY":"b2", "monkey":"c3"}`, `{"API_KEY":"***", "monkey":"c3"}`},
		{"only non-sensitive JSON fields", `{"userAgent":"e5","userId":"f6"}`, `{"userAgent":"e5","userId":"f6"}`},
		{"a number on its own", "42", "42"},
		{"embedded HTTP body", "< HTTP/1.1 200 OK\n< Content-Type: application/json\n\n{\"token\":\"abcdef123456\",\"expires_in\":3600}", "< HTTP/1.1 200 OK\n< Content-Type: application/json\n\n{\"token\":\"***\",\"expires_in\":3600}"},
		{"unclosed quoted value", `{"token":"abcdefgh`, `{"token":"***`},
		{"empty quoted value", `password=""`, `password=""`},
		{"pair nested in a value", `cfg="u: john"`, `cfg="u: ***"`},
		{"double-quoted key next to another field", `fields "u","region":"eu" loaded`, `fields "u","region":"eu" loaded`},
		{"single-quoted key next to another field", `fields 'p','host':'example.com' loaded`, `fields 'p','host':'example.com' loaded`},
		{"unquoted key followed by a comma", `keys u, region: eu`, `keys u, region: eu`},
		{"short key with a colon", `u: john.doe, region: eu`, `u: ***, region: eu`},
		{"escaped quote in a quoted value", `'u': 'Nick\'s', 'other': 'keepme'`, `'u': '***', 'other': 'keepme'`},
		{"double quote inside a double-quoted value", `u: "a"b" next`, `u: "***" next`},
		{"apostrophe inside a single-quoted value", `{ 'p': 'Nick's', 'u': 'x' }`, `{ 'p': '***', 'u': '***' }`},
		{"apostrophe inside a single-quoted password", `password='it's-a-secret'`, `password='***'`},
		{"unquoted values containing quotes", `u: a"b and p: hun'ter2`, `u: *** and p: ***`},
		{"unquoted value containing a quote before a comma", `u: a"b, next: keep`, `u: ***, next: keep`},
		{"quoted value before a separator", `{ 'u': 'john', 'other': 'keep' }`, `{ 'u': '***', 'other': 'keep' }`},
		{"already redacted value", `'u':'***'`, `'u':'***'`},
		{"single-quoted key=value", `before 'u=john.doe' 'p=hunter2' after`, `before 'u=***' 'p=***' after`},
		{"every cookie in a cookie header", "Cookie: session=abc123; other=1", "Cookie: ***"},
		{"cookie header ends at the line end", "set-cookie: sid=abc123xyz; Path=/\nnext line", "set-cookie: ***\nnext line"},
		{"cookies in a go-printed header map", "map[Cookie:[session=abc123; other=1] X-Id:[7]]", "map[Cookie:[***] X-Id:[7]]"},
		{"cookie header without a value", "Cookie:", "Cookie:"},
		{"quoted cookie header", `{"Cookie": "a=1; b=2", "x": 1}`, `{"Cookie": "***", "x": 1}`},
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
				p: hunter2,
				"REGISTRY_USERNAME": "user",
				"REGISTRY_PASSWORD": "foobar",
				"MORE_UNRELATED": "DONT_SCRUB"
			}`,
			`{
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
		"abcdef1":           true,
		"abcdef=":           true,
		"abc+def":           true,
		"abc/def":           true,
		"abcDef":            true,
		"abc1":              false,
		"authentication":    false,
		"Authentication":    false,
		"ABCDEF":            false,
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
		"inner quotes":            strings.Repeat(`p: "x"y `, 8000),
		"inner apostrophes":       strings.Repeat(`'p': 'a'b`, 8000),
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
