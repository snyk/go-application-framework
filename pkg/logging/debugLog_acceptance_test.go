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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
	"github.com/snyk/go-application-framework/pkg/logging"
)

// newDebugLog wires a logger the way a consumer prints human-readable debug output. Write failures are reported into
// the same buffer, because a user sees them in the same stream.
func newDebugLog(t *testing.T, config configuration.Configuration) (*zerolog.Logger, *bytes.Buffer) {
	t.Helper()
	return newDebugLogFor(t, func() configuration.Configuration { return config })
}

func newDebugLogFor(t *testing.T, config func() configuration.Configuration) (*zerolog.Logger, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}

	previousErrorHandler := zerolog.ErrorHandler
	zerolog.ErrorHandler = func(err error) {
		fmt.Fprintf(out, "zerolog: could not write event: %v\n", err)
	}
	t.Cleanup(func() { zerolog.ErrorHandler = previousErrorHandler })

	writer := logging.NewConsoleWriter(out, config, func(w *zerolog.ConsoleWriter) {
		w.NoColor = true
		w.PartsOrder = []string{zerolog.TimestampFieldName, "ext", "separator", zerolog.CallerFieldName, zerolog.MessageFieldName}
		w.FieldsExclude = []string{"ext", "separator"}
	})
	logger := zerolog.New(writer).With().Str("ext", "main").Str("separator", "-").Timestamp().Logger().Level(zerolog.DebugLevel)
	return &logger, out
}

// Fake credentials are assembled at runtime so that secret scanners don't flag the test sources.
func fakeAPIToken() string {
	return strings.Join([]string{"3f9c2b7e", "41d8", "4a6b", "9e2f", "0c5d8a1b7e64"}, "-")
}

func fakeBearerToken() string {
	return strings.Repeat("f8a1c2d3", 4)
}

func fakeGitHubPATSuffix() string {
	return strings.Repeat("Ab12Cd34Ef56", 3)
}

func fakeGitHubPAT() string {
	return "ghp_" + fakeGitHubPATSuffix()
}

func fakeJWTSignature() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("not-a-real-signature"), 2))
}

func fakeJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890"}`))
	return header + "." + payload + "." + fakeJWTSignature()
}

func fakeURLPassword() string {
	return strings.Repeat("Pw0rd", 3)
}

func fakeURLPasswordParts() (string, string) {
	return strings.Repeat("Kq7", 2), strings.Repeat("Zp9", 2)
}

func fakeLowercaseCredential() string {
	return strings.Repeat("qwertyuiop", 2)
}

func configWithRedactionTerms(terms ...string) configuration.Configuration {
	config := configuration.NewWithOpts()
	config.Set(logging.REDACTION_TERMS, terms)
	return config
}

func withExt(logger *zerolog.Logger, ext string) zerolog.Logger {
	if ext == "" {
		return *logger
	}
	return logger.With().Str("ext", ext).Logger()
}

func requireEventShown(t *testing.T, out *bytes.Buffer, message string) string {
	t.Helper()
	shown := out.String()
	assert.NotContains(t, shown, "could not write event")
	require.Contains(t, shown, message, "the debug event is missing from the output")
	return shown
}

func TestDebugLog_PasswordFieldIsRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Str("password", "correct-horse-battery").Msg("proxy configured")

	shown := requireEventShown(t, out, "proxy configured")
	assert.Contains(t, shown, "password=***")
	assert.NotContains(t, shown, "correct-horse-battery")
}

func TestDebugLog_SecretContainingAQuoteIsRedactedWithoutDroppingTheEvent(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Str("token", `hunter"twoSecret`).Msg("loaded credentials")

	shown := requireEventShown(t, out, "loaded credentials")
	assert.NotContains(t, shown, "hunter")
	assert.NotContains(t, shown, "twoSecret")
}

func TestDebugLog_FieldAfterAURLIsShownWhenItContainsAnAtSign(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Str("url", "https://api.example.com:443/v1/x").Str("email", "a@b.com").Msg("sending request")

	shown := requireEventShown(t, out, "sending request")
	assert.Contains(t, shown, "https://api.example.com:443/v1/x")
	assert.Contains(t, shown, "email=a@b.com")
}

func TestDebugLog_SensitiveFieldWithANumberValueIsRedactedWithoutDroppingTheEvent(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Int("token", 987654321).Msg("credentials refreshed")

	shown := requireEventShown(t, out, "credentials refreshed")
	assert.NotContains(t, shown, "987654321")
}

func TestDebugLog_ShortFormCredentialFieldsWithNumberOrBoolValuesAreShownRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Int("p", 5).Bool("u", true).Msg("parsed short options")

	shown := requireEventShown(t, out, "parsed short options")
	assert.Contains(t, shown, "p=***")
	assert.Contains(t, shown, "u=***")
}

func TestDebugLog_NestedSensitiveFieldsAreRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Interface("auth", map[string]interface{}{
		"profiles": []interface{}{map[string]interface{}{"name": "work", "password": "nested-pass-value"}},
		"note":     "Bearer " + fakeBearerToken(),
	}).Msg("loaded profiles")

	shown := requireEventShown(t, out, "loaded profiles")
	assert.Contains(t, shown, "work")
	assert.NotContains(t, shown, "nested-pass-value")
	assert.NotContains(t, shown, fakeBearerToken())
}

func TestDebugLog_FieldNameMatchingARedactionTermIsNotRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configWithRedactionTerms("Content", "reference", "command"))

	logger.Debug().Str("command", "snyk test").Msg("running")

	shown := requireEventShown(t, out, "running")
	assert.Contains(t, shown, `command="snyk test"`)
}

func TestDebugLog_StandaloneRedactionTermIsStillRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configWithRedactionTerms("Content", "reference", "command"))

	logger.Debug().Str("value", "reference").Msg("resolved the reference value")

	shown := requireEventShown(t, out, "resolved the *** value")
	assert.Contains(t, shown, "value=***")
	assert.NotContains(t, shown, "reference")
}

func TestDebugLog_FieldAfterArgumentsEndingInAShortFlagIsShown(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Str("args", "snyk test -u").Str("command", "monitor").Msg("dispatching")

	shown := requireEventShown(t, out, "dispatching")
	assert.Contains(t, shown, `args="snyk test -u"`)
	assert.Contains(t, shown, "command=monitor")
}

func TestDebugLog_ShortFormCredentialsContainingAQuoteAreRedactedWhole(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg(`proxy login u: a"b p: hun"ter2 done`)

	shown := requireEventShown(t, out, "proxy login u: *** p: *** done")
	assert.NotContains(t, shown, `"b`)
	assert.NotContains(t, shown, "ter2")
}

func TestDebugLog_ProseWithShortWordsBeforeASeparatorIsShown(t *testing.T) {
	for _, message := range []string{
		`opening P:\projects\foo\file.go`,
		"GET /items?p=3",
		"cache key: abc",
	} {
		t.Run(message, func(t *testing.T) {
			logger, out := newDebugLog(t, configuration.NewWithOpts())

			logger.Debug().Msg(message)

			requireEventShown(t, out, message)
		})
	}
}

func TestDebugLog_OrdinaryCommandsWithShortFlagsAreShown(t *testing.T) {
	for _, command := range []string{
		"mkdir -p /tmp/x",
		"ps -p 123",
		"docker run -p 8080:80 img",
	} {
		t.Run(command, func(t *testing.T) {
			logger, out := newDebugLog(t, configuration.NewWithOpts())

			logger.Debug().Msg("running " + command)

			requireEventShown(t, out, "running "+command)
		})
	}
}

func TestDebugLog_LongCredentialFlagsAreRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("container test img --username jdoe --password hunter2 --password=hunter3 --token tkn-value --org=acme")

	shown := requireEventShown(t, out, "container test img --username *** --password *** --password=*** --token *** --org=acme")
	assert.NotContains(t, shown, "hunter")
}

func TestDebugLog_BearerTokenInAnAuthorizationHeaderIsRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("> Authorization: Bearer " + fakeBearerToken())

	shown := requireEventShown(t, out, "> Authorization: Bearer ***")
	assert.NotContains(t, shown, fakeBearerToken())
}

func TestDebugLog_LowercaseBasicCredentialInAnAuthorizationHeaderIsRedacted(t *testing.T) {
	credential := fakeLowercaseCredential()
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("> Authorization: Basic " + credential)

	shown := requireEventShown(t, out, "> Authorization: Basic ***")
	assert.NotContains(t, shown, credential)
}

func TestDebugLog_CredentialsInAURLAreRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("cloning https://someone:" + fakeURLPassword() + "@git.example.com/org/repo.git")

	shown := requireEventShown(t, out, "cloning https://***@git.example.com/org/repo.git")
	assert.NotContains(t, shown, fakeURLPassword())
}

func TestDebugLog_URLPasswordContainingAnAtSignIsRedactedWhole(t *testing.T) {
	before, after := fakeURLPasswordParts()
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("cloning https://someone:" + before + "@" + after + "@git.example.com/org/repo.git")

	shown := requireEventShown(t, out, "cloning https://***@git.example.com/org/repo.git")
	assert.NotContains(t, shown, before)
	assert.NotContains(t, shown, after)
}

func TestDebugLog_URLFollowedByAnEmailAddressInTheSameMessageIsShown(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("cloning https://api.example.com:8443/org/repo for dev@example.com")

	requireEventShown(t, out, "cloning https://api.example.com:8443/org/repo for dev@example.com")
}

func TestDebugLog_JWTInAnAccessTokenFieldIsRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Str("access_token", fakeJWT()).Msg("received oauth response")

	shown := requireEventShown(t, out, "received oauth response")
	assert.NotContains(t, shown, "eyJ")
	assert.NotContains(t, shown, fakeJWTSignature())
}

func TestDebugLog_GitHubPersonalAccessTokenIsRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("using credential " + fakeGitHubPAT())

	shown := requireEventShown(t, out, "using credential ghp_***")
	assert.NotContains(t, shown, fakeGitHubPATSuffix())
}

func TestDebugLog_EveryKindOfGitHubTokenIsRedacted(t *testing.T) {
	for _, prefix := range []string{"gho_", "ghu_", "ghs_", "ghr_"} {
		t.Run(prefix, func(t *testing.T) {
			logger, out := newDebugLog(t, configuration.NewWithOpts())

			logger.Debug().Msg("using credential " + prefix + fakeGitHubPATSuffix())

			shown := requireEventShown(t, out, "using credential "+prefix+"***")
			assert.NotContains(t, shown, fakeGitHubPATSuffix())
		})
	}
}

func TestDebugLog_ConfiguredAPITokenIsRedactedWhereverItAppears(t *testing.T) {
	apiToken := fakeAPIToken()
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, apiToken)
	logger, out := newDebugLog(t, config)

	logger.Debug().Str("env", "SNYK_CFG="+apiToken).Str(apiToken, "as a field name").Msgf("authenticating with %s", apiToken)

	shown := requireEventShown(t, out, "authenticating with ***")
	assert.Contains(t, shown, "as a field name")
	assert.NotContains(t, shown, apiToken)
}

func TestDebugLog_ConfiguredSecretJoinedByHyphenOrDotIsStillRedacted(t *testing.T) {
	apiToken := fakeAPIToken()
	config := configWithRedactionTerms("Content", "reference", "command")
	config.Set(configuration.AUTHENTICATION_TOKEN, apiToken)
	logger, out := newDebugLog(t, config)

	logger.Debug().Str("header", "prefix-"+apiToken).Msgf("cached under %s.suffix", apiToken)

	shown := requireEventShown(t, out, "cached under ***.suffix")
	assert.Contains(t, shown, "header=prefix-***")
	assert.NotContains(t, shown, apiToken)
}

func TestDebugLog_SecretsStayRedactedNextToEnvironmentTerms(t *testing.T) {
	apiToken := fakeAPIToken()
	proxyPassword := fakeURLPassword()
	config := configWithRedactionTerms("token", "Content", "child", "Version:", "using")
	config.Set(configuration.AUTHENTICATION_TOKEN, apiToken)
	base, out := newDebugLog(t, config)
	legacy := withExt(base, "legacy:2")

	base.Debug().Msgf("> request [0x1]: header: map[Authorization:[token %s] Content-Type:[application/json] Session-Token:[token %s] User-Agent:[example-app/1.0.0 (linux;amd64)] X-App-Version:[1.0.0]]", apiToken, apiToken)
	legacy.Debug().Msgf("HTTPS_PROXY = http://proxyuser:%s@127.0.0.1:41234", proxyPassword)
	legacy.Debug().Msgf("client using proxy: http://proxyuser:%s@127.0.0.1:41234", proxyPassword)
	base.Debug().Msgf("cached %s for this session", apiToken)

	shown := requireEventShown(t, out, "> request [0x1]: header: map[Authorization:[*** ***] Content-Type:[application/json] Session-Token:[*** ***] User-Agent:[example-app/1.0.0 (linux;amd64)] X-App-Version:[1.0.0]]")
	assert.Contains(t, shown, "legacy:2 - HTTPS_PROXY = http://***@127.0.0.1:41234\n")
	assert.Contains(t, shown, "legacy:2 - client *** proxy: http://***@127.0.0.1:41234\n")
	assert.Contains(t, shown, "main - cached *** for this session\n")
	assert.NotContains(t, shown, apiToken)
	assert.NotContains(t, shown, proxyPassword)
}

func TestDebugLog_HyphenatedNamesSurviveEnvironmentTerms(t *testing.T) {
	base, out := newDebugLog(t, configWithRedactionTerms("Content", "reference", "depth", "script", "login", "cycle", "group", "child"))
	legacy := withExt(base, "legacy:2")

	legacy.Debug().Msg("monitor /home/ci/project --org=example-org --target-reference=feature-x --detection-depth=3 --project-lifecycle=production --all-projects -d")
	base.Debug().Msg("< response [0x2]: header: map[Content-Security-Policy:[script-src 'self'; frame-ancestors https://login.example.com; report-to csp-report-group] X-Content-Type-Options:[nosniff]]")

	shown := requireEventShown(t, out, "--target-reference=feature-x")
	for _, visible := range []string{"--detection-depth=3", "--project-lifecycle=production", "Content-Security-Policy", "script-src", "login.example.com", "csp-report-group", "X-Content-Type-Options"} {
		assert.Contains(t, shown, visible)
	}
}

func TestDebugLog_ProseMentioningAuthSchemesIsNotRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("Using token authentication and Basic authentication flow")
	logger.Debug().Msg("refreshing the token because the server rejected the Bearer request")

	requireEventShown(t, out, "Using token authentication and Basic authentication flow")
	requireEventShown(t, out, "refreshing the token because the server rejected the Bearer request")
}

func TestDebugLog_UUIDShapedTokenInProseIsRedacted(t *testing.T) {
	apiToken := fakeAPIToken()
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("using token " + apiToken + " for this request")

	shown := requireEventShown(t, out, "using token *** for this request")
	assert.NotContains(t, shown, apiToken)
}

func TestDebugLog_FieldsWhoseNamesMerelyContainKeyOrUserKeepTheirValues(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Str("userAgent", "snyk-cli/1.0").Str("cacheKey", "deps-lockfile").Str("monkey", "banana").Str("keyId", "k-1").Msg("cache lookup")

	shown := requireEventShown(t, out, "cache lookup")
	assert.Contains(t, shown, "userAgent=snyk-cli/1.0")
	assert.Contains(t, shown, "cacheKey=deps-lockfile")
	assert.Contains(t, shown, "monkey=banana")
	assert.Contains(t, shown, "keyId=k-1")
}

func TestDebugLog_CountOfUsersIsShown(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Int("users", 3).Msg("org loaded")

	shown := requireEventShown(t, out, "org loaded")
	assert.Contains(t, shown, "users=3")
}

func TestDebugLog_FieldsDescribingTokensKeepTheirValues(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Int("tokenCount", 42).Int("max_tokens", 4096).Str("token_type", "bearer").Int("token_expiry", 3600).Int("tokenLength", 40).Msg("completion received")

	shown := requireEventShown(t, out, "completion received")
	assert.Contains(t, shown, "tokenCount=42")
	assert.Contains(t, shown, "max_tokens=4096")
	assert.Contains(t, shown, "token_type=bearer")
	assert.Contains(t, shown, "token_expiry=3600")
	assert.Contains(t, shown, "tokenLength=40")
}

func TestDebugLog_EmbeddedJSONBodyIsRedactedByFieldName(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg(`> body: {"login":"someone","password":"` + fakeLowercaseCredential() + `","cacheKey":"deps-lockfile","userAgent":"snyk-cli/1.0"}`)

	shown := requireEventShown(t, out, `"cacheKey":"deps-lockfile","userAgent":"snyk-cli/1.0"}`)
	assert.Contains(t, shown, `{"login":"***","password":"***"`)
}

func TestDebugLog_SensitiveFieldsAreRedacted(t *testing.T) {
	for _, name := range []string{
		"apiKey", "x-api-key", "client_secret", "userName", "Authorization", "Set-Cookie", "secrets", "tokens",
		"passwords", "cookies", "apiKeys", "api_keys", "authorizations", "REGISTRY_USERNAME", "PROXY_USER",
		"registryUserName", "proxy-user", "requestHeaders", "response_headers", "apikey", "accesskey", "authtoken",
		"clientsecret", "sessionKey", "passcode", "secretValue", "tokenValue", "privateKeyPem", "passwordHash",
		"signingKey", "apiKeyId",
	} {
		t.Run(name, func(t *testing.T) {
			logger, out := newDebugLog(t, configuration.NewWithOpts())

			logger.Debug().Str(name, fakeLowercaseCredential()).Msg("request prepared")

			shown := requireEventShown(t, out, name+"=***")
			assert.NotContains(t, shown, fakeLowercaseCredential())
		})
	}
}

// Redaction terms are tokens of the environment and the command line, so a term can carry a quote or
// a trailing comma from a quoted or JSON-shaped value. Each case logs a debug event containing such a term.
func TestDebugLog_EventsSurviveTermsCarryingJSONPunctuation(t *testing.T) {
	analyticsPayload := "{\n  \"standalone\": true,\n  \"ci\": true,\n  \"durationMs\": 1234,\n  \"metrics\": {\n    \"network_time\": {\n      \"type\": \"timer\",\n      \"values\": [\n        12,\n        34\n      ]\n    }\n  }\n}"
	redactedAnalyticsPayload := "{\n  \"standalone\": ***\n  \"ci\": ***\n  \"durationMs\": 1234,\n  ***\": {\n    \"network_time\": {\n      \"type\": \"timer\",\n      \"values\": [\n        12,\n        34\n      ]\n    }\n  }\n}"
	analyticsData := `[0] Data: {"data":{"attributes":{"runtime":{"application":{"name":"example-app","version":"1.0.0-example"}},"interaction":{"extension":{"legacy::metadata__depGraph":true,"legacy::metadata__isDocker":false}}}}}`
	redactedAnalyticsData := `[0] Data: {"data":{"attributes":{"runtime":{"application":{***":"example-app","version":"1.0.0-example"}},"interaction":{"extension":{"legacy::metadata__depGraph":***"legacy::metadata__isDocker":false}}}}}`

	cases := []struct {
		name     string
		ext      string
		level    zerolog.Level
		message  string
		terms    []string
		expected string
	}{
		{"running command", "", zerolog.DebugLevel, `Running monitor with args "Running test"`, []string{`"Running`}, `Running monitor with args *** test"`},
		{"extra CA file", "legacy:2", zerolog.DebugLevel, `Using additional CAs from file: "Using /opt/ci/certs/extra-ca.pem`, []string{`"Using`}, "Using additional CAs from file: *** /opt/ci/certs/extra-ca.pem"},
		{"proxy connect result", "legacy:2", zerolog.DebugLevel, `"HandleConnect - basic authentication result: &{0 <nil> 0x1a2b3c0}api.example.com:443`, []string{`"Handle`, "result:"}, `"HandleConnect - basic authentication *** &{0 <nil> 0x1a2b3c0}api.example.com:443`},
		{"multi-line analytics dump", "legacy:2", zerolog.DebugLevel, analyticsPayload, []string{`"metrics`, "true,"}, redactedAnalyticsPayload},
		{"output writers count", "output:4", zerolog.InfoLevel, `Available writers (count: 1): info" text/cli`, []string{`info"`}, "Available writers (count: 1): *** text/cli"},
		{"output writer map", "output:4", zerolog.InfoLevel, `WriterMap: (default -> text/cli) info"`, []string{`info"`}, "WriterMap: (default -> text/cli) ***"},
		{"no unified findings", "output:4", zerolog.InfoLevel, `UFM - No data to process at info"`, []string{`info"`}, "UFM - No data to process at ***"},
		{"no local findings", "output:4", zerolog.InfoLevel, `LFM - No findings to process at info"`, []string{`info"`}, "LFM - No findings to process at ***"},
		{"no other data", "output:4", zerolog.InfoLevel, `Other - No data to process at info"`, []string{`info"`}, "Other - No data to process at ***"},
		{"sending analytics", "", zerolog.DebugLevel, `Sending Analytics for "Sending`, []string{`"Sending`}, "Sending Analytics for ***"},
		{"sending instrumentation", "", zerolog.DebugLevel, `Sending Instrumentation for "Sending`, []string{`"Sending`}, "Sending Instrumentation for ***"},
		{"analytics report data", "analytics.report:5", zerolog.DebugLevel, analyticsData, []string{`"name`, "true,"}, redactedAnalyticsData},
		{"authorization summary", "", zerolog.DebugLevel, `"Authorization: summary  (type=token)`, []string{`"Authorization:`}, "***  (type=token)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, out := newDebugLog(t, configWithRedactionTerms(tc.terms...))
			logger := withExt(base, tc.ext)

			logger.WithLevel(tc.level).Msg(tc.message)

			requireEventShown(t, out, tc.expected)
		})
	}
}

func TestDebugLog_BareBooleanFieldSurvivesTermWithTrailingComma(t *testing.T) {
	logger, out := newDebugLog(t, configWithRedactionTerms("true,"))

	logger.Debug().Bool("cached", true).Str("flags", "cached=true, source=example").Msg("feature flag evaluated")

	shown := requireEventShown(t, out, "feature flag evaluated")
	assert.Contains(t, shown, "cached=true ")
	assert.Contains(t, shown, `flags="cached=*** source=example"`)
}

func TestDebugLog_ConsumerFormattingOptionsKeepWorkingWithRedaction(t *testing.T) {
	out := &bytes.Buffer{}
	config := configuration.NewWithOpts()
	writer := logging.NewConsoleWriter(out, func() configuration.Configuration { return config }, func(w *zerolog.ConsoleWriter) {
		w.NoColor = true
		w.FormatTimestamp = func(interface{}) string { return "TIMESTAMP" }
		w.FormatPrepare = func(event map[string]interface{}) error {
			event["password"] = "added-by-consumer"
			return nil
		}
	})
	logger := zerolog.New(writer).With().Timestamp().Logger()

	logger.Info().Msg("formatted")

	shown := out.String()
	assert.Contains(t, shown, "TIMESTAMP")
	assert.Contains(t, shown, "password=***")
	assert.NotContains(t, shown, "added-by-consumer")
}

func TestDebugLog_TokenLoggedWhileAnotherEventReadsTheConfigurationIsRedacted(t *testing.T) {
	config := configuration.NewWithOpts()
	firstReadStarted, releaseFirstRead := blockFirstReadOfRedactionTerms(t, config)
	logger, out := newDebugLog(t, config)
	firstEventLogged := make(chan struct{})
	go func() {
		defer close(firstEventLogged)
		logger.Debug().Msg("first event")
	}()
	waitFor(t, firstReadStarted, "the first event to read the configuration")

	apiToken := fakeAPIToken()
	config.Set(configuration.AUTHENTICATION_TOKEN, apiToken)
	logger.Debug().Msgf("authenticating with %s", apiToken)
	releaseFirstRead()
	waitFor(t, firstEventLogged, "the first event to be logged")
	logger.Debug().Msgf("still authenticating with %s", apiToken)

	shown := requireEventShown(t, out, "authenticating with ***")
	assert.Contains(t, shown, "first event")
	assert.Contains(t, shown, "still authenticating with ***")
	assert.NotContains(t, shown, apiToken)
}

func TestDebugLog_SecretsOfTheSelectedProfileAreRedacted(t *testing.T) {
	baseToken := fakeBearerToken()
	base := configuration.NewWithOpts(configuration.WithPinnedFile(filepath.Join(t.TempDir(), "snyk.json")))
	base.Set(configuration.AUTHENTICATION_TOKEN, baseToken)
	var current atomic.Pointer[configuration.Configuration]
	current.Store(&base)
	logger, out := newDebugLogFor(t, func() configuration.Configuration { return *current.Load() })
	logger.Debug().Msg("starting")

	profileToken := fakeAPIToken()
	profileDir := t.TempDir()
	content := fmt.Sprintf(`{%q: %q, %q: ["profile-only-term"]}`, configuration.AUTHENTICATION_TOKEN, profileToken, logging.REDACTION_TERMS)
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "work.json"), []byte(content), 0o600))
	registry, err := profile.NewFileRegistry(profileDir, base)
	require.NoError(t, err)
	selected, err := registry.Profile("work")
	require.NoError(t, err)
	profileConfig := selected.Configuration()
	current.Store(&profileConfig)

	logger.Debug().Msgf("profile has %s, base had %s, term profile-only-term", profileToken, baseToken)

	shown := requireEventShown(t, out, "profile has ***, base had ***, term ***")
	assert.NotContains(t, shown, profileToken)
	assert.NotContains(t, shown, baseToken)
}

// blockFirstReadOfRedactionTerms holds the first reader of REDACTION_TERMS until release is called, so a test can act
// while a redaction is in the middle of reading the configuration. The reader is released when the test ends, too.
func blockFirstReadOfRedactionTerms(t *testing.T, config configuration.Configuration) (started <-chan struct{}, release func()) {
	t.Helper()
	startedCh, releaseCh := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(releaseCh) }) }
	t.Cleanup(release)
	var first atomic.Bool
	config.AddDefaultValue(logging.REDACTION_TERMS, func(_ configuration.Configuration, existing interface{}) (interface{}, error) {
		if first.CompareAndSwap(false, true) {
			close(startedCh)
			<-releaseCh
		}
		return existing, nil
	})
	return startedCh, release
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestDebugLog_ShortCredentialAfterAnAuthSchemeIsRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("retrying with Bearer abc+def and Basic auth456")

	shown := requireEventShown(t, out, "retrying with Bearer *** and Basic ***")
	assert.NotContains(t, shown, "abc+def")
	assert.NotContains(t, shown, "auth456")
}

func TestDebugLog_TextAfterARedactedCredentialIsShown(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg(`<a href="x">Bearer ` + fakeBearerToken() + `</a> sent`)

	shown := requireEventShown(t, out, `<a href="x">Bearer ***</a> sent`)
	assert.NotContains(t, shown, fakeBearerToken())
}

func TestDebugLog_QuotedPasswordContainingAQuoteIsRedactedWhole(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg(`proxy login password='it's-a-secret' p: "hun"ter2" done`)

	shown := requireEventShown(t, out, `proxy login password='***' p: "***" done`)
	assert.NotContains(t, shown, "secret")
	assert.NotContains(t, shown, "ter2")
}

func TestDebugLog_TermInsideANonASCIIWordIsShown(t *testing.T) {
	logger, out := newDebugLog(t, configWithRedactionTerms("quest"))

	logger.Debug().Msg("préquest and quest")

	requireEventShown(t, out, "préquest and ***")
}

func TestDebugLog_EveryCookieInACookieHeaderIsRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("> Cookie: session=first-cookie-value; theme=second-cookie-value")

	shown := requireEventShown(t, out, "> Cookie: ***")
	assert.NotContains(t, shown, "first-cookie-value")
	assert.NotContains(t, shown, "second-cookie-value")
}
