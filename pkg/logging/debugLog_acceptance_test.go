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
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
)

// newDebugLog wires a logger the way a consumer prints human-readable debug output: the scrubbing
// writer in front of zerolog's ConsoleWriter, which decodes the scrubbed JSON a second time. Write
// failures are reported into the same buffer, because a user sees them in the same stream.
func newDebugLog(t *testing.T, config configuration.Configuration) (*zerolog.Logger, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}

	previousErrorHandler := zerolog.ErrorHandler
	zerolog.ErrorHandler = func(err error) {
		fmt.Fprintf(out, "zerolog: could not write event: %v\n", err)
	}
	t.Cleanup(func() { zerolog.ErrorHandler = previousErrorHandler })

	consoleWriter := zerolog.ConsoleWriter{
		Out:           out,
		NoColor:       true,
		PartsOrder:    []string{zerolog.TimestampFieldName, "ext", "separator", zerolog.CallerFieldName, zerolog.MessageFieldName},
		FieldsExclude: []string{"ext", "separator"},
	}
	scrubWriter := logging.NewScrubbingWriter(zerolog.MultiLevelWriter(consoleWriter), logging.GetScrubDictFromConfig(config))
	logger := zerolog.New(scrubWriter).With().Str("ext", "main").Str("separator", "-").Timestamp().Logger().Level(zerolog.DebugLevel)
	return &logger, out
}

// Fake credentials are assembled at runtime so that secret scanners don't flag the test sources.
func fakeAPIToken() string {
	return strings.Join([]string{"3f9c2b7e", "41d8", "4a6b", "9e2f", "0c5d8a1b7e64"}, "-")
}

func fakeBearerToken() string {
	return strings.Repeat("f8a1c2d3", 4)
}

func fakeLowercaseCredential() string {
	return strings.Repeat("qwertyuiop", 2)
}

func fakeURLPasswordParts() (string, string) {
	return strings.Repeat("Kq7", 2), strings.Repeat("Zp9", 2)
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

func configWithRedactionTerms(terms ...string) configuration.Configuration {
	config := configuration.NewWithOpts()
	config.Set(logging.REDACTION_TERMS, terms)
	return config
}

func requireEventShown(t *testing.T, out *bytes.Buffer, message string) string {
	t.Helper()
	shown := out.String()
	assert.NotContains(t, shown, "could not write event")
	assert.NotContains(t, shown, "cannot decode event")
	require.Contains(t, shown, message, "the debug event is missing from the output")
	return shown
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

func TestDebugLog_ShortFormCredentialFieldsWithNumberOrBoolValuesDoNotDropTheEvent(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Int("p", 5).Bool("u", true).Msg("parsed short options")

	requireEventShown(t, out, "parsed short options")
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
	assert.Contains(t, shown, "command=monitor")
}

func TestDebugLog_ShortFormCredentialsContainingAQuoteAreRedactedWhole(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg(`proxy login u: a"b p: hun"ter2 done`)

	shown := requireEventShown(t, out, "proxy login u: *** p: *** done")
	assert.NotContains(t, shown, `"b`)
	assert.NotContains(t, shown, "ter2")
}

func TestDebugLog_BearerTokenInAnAuthorizationHeaderIsRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("> Authorization: Bearer " + fakeBearerToken())

	shown := requireEventShown(t, out, "> Authorization: Bearer ***")
	assert.NotContains(t, shown, fakeBearerToken())
}

func TestDebugLog_CredentialsInAURLAreRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("cloning https://someone:" + fakeURLPassword() + "@git.example.com/org/repo.git")

	shown := requireEventShown(t, out, "cloning https://")
	assert.NotContains(t, shown, fakeURLPassword())
	assert.Contains(t, shown, "git.example.com/org/repo.git")
}

func TestDebugLog_JWTInAnAccessTokenFieldIsRedacted(t *testing.T) {
	jwt := fakeJWT()
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Str("access_token", jwt).Msg("received oauth response")

	shown := requireEventShown(t, out, "received oauth response")
	assert.NotContains(t, shown, "eyJ")
	assert.NotContains(t, shown, fakeJWTSignature())
}

func TestDebugLog_GitHubPersonalAccessTokenIsRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("using credential " + fakeGitHubPAT())

	shown := requireEventShown(t, out, "using credential ghp_")
	assert.NotContains(t, shown, fakeGitHubPATSuffix())
}

func TestDebugLog_ConfiguredAPITokenIsRedactedWhereverItAppears(t *testing.T) {
	apiToken := fakeAPIToken()
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, apiToken)
	logger, out := newDebugLog(t, config)

	logger.Debug().Str("env", "SNYK_CFG="+apiToken).Msgf("authenticating with %s", apiToken)

	shown := requireEventShown(t, out, "authenticating with ***")
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

func TestDebugLog_PasswordFieldIsRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Str("password", "correct-horse-battery").Msg("proxy configured")

	shown := requireEventShown(t, out, "proxy configured")
	assert.Contains(t, shown, "password=***")
	assert.NotContains(t, shown, "correct-horse-battery")
}

func withExt(logger *zerolog.Logger, ext string) zerolog.Logger {
	if ext == "" {
		return *logger
	}
	return logger.With().Str("ext", ext).Logger()
}

// Redaction terms are tokens of the environment and the command line, so a term can carry a quote or
// a trailing comma from a quoted or JSON-shaped value. Each case pairs a debug event with such a term.
func TestDebugLog_EventsSurviveTermsCarryingJSONPunctuation(t *testing.T) {
	analyticsPayload := "{\n  \"standalone\": true,\n  \"ci\": true,\n  \"durationMs\": 1234,\n  \"metrics\": {\n    \"network_time\": {\n      \"type\": \"timer\",\n      \"values\": [\n        12,\n        34\n      ]\n    }\n  }\n}"
	analyticsData := `[0] Data: {"data":{"attributes":{"runtime":{"application":{"name":"example-app","version":"1.0.0-example"}},"interaction":{"extension":{"legacy::metadata__depGraph":true,"legacy::metadata__isDocker":false}}}}}`

	cases := []struct {
		name    string
		ext     string
		level   zerolog.Level
		message string
		terms   []string
		visible string
	}{
		{"running command", "", zerolog.DebugLevel, "Running monitor", []string{`"Running`}, "monitor"},
		{"extra CA file", "legacy:2", zerolog.DebugLevel, "Using additional CAs from file: /opt/ci/certs/extra-ca.pem", []string{`"Using`}, "additional CAs"},
		{"proxy connect result", "legacy:2", zerolog.DebugLevel, "HandleConnect - basic authentication result: &{0 <nil> 0x1a2b3c0}api.example.com:443", []string{`"Handle`, "result:"}, "HandleConnect"},
		{"multi-line analytics dump", "legacy:2", zerolog.DebugLevel, analyticsPayload, []string{`"metrics`, "true,"}, "network_time"},
		{"output writers count", "output:4", zerolog.InfoLevel, "Available writers (count: 1):", []string{`info"`}, "Available writers"},
		{"output writer map", "output:4", zerolog.InfoLevel, "WriterMap: (default -> text/cli) ", []string{`info"`}, "WriterMap"},
		{"no unified findings", "output:4", zerolog.InfoLevel, "UFM - No data to process", []string{`info"`}, "UFM"},
		{"no local findings", "output:4", zerolog.InfoLevel, "LFM - No findings to process", []string{`info"`}, "LFM"},
		{"no other data", "output:4", zerolog.InfoLevel, "Other - No data to process", []string{`info"`}, "Other"},
		{"sending analytics", "", zerolog.DebugLevel, "Sending Analytics", []string{`"Sending`}, "Analytics"},
		{"sending instrumentation", "", zerolog.DebugLevel, "Sending Instrumentation", []string{`"Sending`}, "Instrumentation"},
		{"analytics report data", "analytics.report:5", zerolog.DebugLevel, analyticsData, []string{`"name`, "true,"}, "example-app"},
		{"authorization summary", "", zerolog.DebugLevel, "Authorization:         1a2b3c4d***9f8e7d6c  (type=token)", []string{`"Authorization:`}, "(type=token)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, out := newDebugLog(t, configWithRedactionTerms(tc.terms...))
			logger := withExt(base, tc.ext)

			logger.WithLevel(tc.level).Msg(tc.message)

			requireEventShown(t, out, tc.visible)
		})
	}
}

func TestDebugLog_BareBooleanFieldSurvivesTermWithTrailingComma(t *testing.T) {
	logger, out := newDebugLog(t, configWithRedactionTerms("true,"))

	logger.Debug().Bool("cached", true).Str("source", "example").Msg("feature flag evaluated")

	requireEventShown(t, out, "feature flag evaluated")
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

	shown := requireEventShown(t, out, "Content-Type:[application/json]")
	assert.NotContains(t, shown, apiToken)
	assert.NotContains(t, shown, proxyPassword)
}

func TestDebugLog_HyphenatedNamesSurviveEnvironmentTerms(t *testing.T) {
	base, out := newDebugLog(t, configWithRedactionTerms("Content", "reference", "depth", "script", "login", "cycle", "group", "child"))
	legacy := withExt(base, "legacy:2")

	legacy.Debug().Msg("monitor /home/ci/project --org=example-org --target-reference=feature-x --detection-depth=3 --project-lifecycle=production --all-projects -d")
	base.Debug().Msg("< response [0x2]: header: map[Content-Security-Policy:[script-src 'self'; frame-ancestors https://login.example.com; report-to csp-report-group] X-Content-Type-Options:[nosniff]]")

	shown := requireEventShown(t, out, "--target-reference=")
	for _, visible := range []string{"--detection-depth=3", "--project-lifecycle=production", "Content-Security-Policy", "script-src", "login.example.com", "csp-report-group", "X-Content-Type-Options"} {
		assert.Contains(t, shown, visible)
	}
}

func TestDebugLog_ProseMentioningTokenOrBasicAuthenticationIsNotRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("Using token authentication and Basic authentication flow")

	requireEventShown(t, out, "Using token authentication and Basic authentication flow")
}

func TestDebugLog_LowercaseWordAfterTokenOrBearerInProseIsNotRedacted(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("refreshing the token because the server rejected the Bearer request")

	requireEventShown(t, out, "refreshing the token because the server rejected the Bearer request")
}

func TestDebugLog_UUIDShapedTokenInProseIsRedacted(t *testing.T) {
	apiToken := fakeAPIToken()
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("using token " + apiToken + " for this request")

	shown := requireEventShown(t, out, "using token *** for this request")
	assert.NotContains(t, shown, apiToken)
}

func TestDebugLog_LowercaseBasicCredentialInAnAuthorizationHeaderIsRedacted(t *testing.T) {
	credential := fakeLowercaseCredential()
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("> Authorization: Basic " + credential)

	shown := requireEventShown(t, out, "> Authorization: Basic ***")
	assert.NotContains(t, shown, credential)
}

func TestDebugLog_URLFollowedByAnEmailAddressInTheSameMessageIsShown(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("cloning https://api.example.com:8443/org/repo for dev@example.com")

	requireEventShown(t, out, "cloning https://api.example.com:8443/org/repo for dev@example.com")
}

func TestDebugLog_URLPasswordContainingAnAtSignIsRedactedWhole(t *testing.T) {
	before, after := fakeURLPasswordParts()
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Msg("cloning https://someone:" + before + "@" + after + "@git.example.com/org/repo.git")

	shown := requireEventShown(t, out, "cloning https://***@git.example.com/org/repo.git")
	assert.NotContains(t, shown, before)
	assert.NotContains(t, shown, after)
}

func TestDebugLog_FieldsWhoseNamesMerelyContainKeyOrUserKeepTheirValues(t *testing.T) {
	logger, out := newDebugLog(t, configuration.NewWithOpts())

	logger.Debug().Str("userAgent", "snyk-cli/1.0").Str("cacheKey", "deps-lockfile").Str("monkey", "banana").Msg("cache lookup")

	shown := requireEventShown(t, out, "cache lookup")
	assert.Contains(t, shown, "userAgent=snyk-cli/1.0")
	assert.Contains(t, shown, "cacheKey=deps-lockfile")
	assert.Contains(t, shown, "monkey=banana")
}
