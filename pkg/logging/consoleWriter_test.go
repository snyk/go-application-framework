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
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
)

func noColor(w *zerolog.ConsoleWriter) { w.NoColor = true }

func withToken(token string) func(configuration.Configuration) {
	return withValue(configuration.AUTHENTICATION_TOKEN, token)
}

func withTerms(terms ...string) func(configuration.Configuration) {
	return func(config configuration.Configuration) { config.Set(logging.REDACTION_TERMS, terms) }
}

func withValue(key string, value interface{}) func(configuration.Configuration) {
	return func(config configuration.Configuration) { config.Set(key, value) }
}

func TestConsoleWriter_ShowsEachEventWithoutItsSecrets(t *testing.T) {
	const secret = "s3cr3tvalue99"
	allSecrets, allSecretsEvent, configureAllSecrets := everyKindOfSecret(t)

	tests := []struct {
		name      string
		configure func(configuration.Configuration)
		event     string
		shown     []string
		absent    []string
	}{
		{"term as a JSON number", withTerms("12345"), `{"count":12345}`, []string{"count=***"}, []string{"12345"}},
		{"term as a whole JSON string", withTerms("request"), `{"result":"no_relevant_request","note":"request"}`, []string{"result=no_relevant_request", "note=***"}, nil},

		{"token as a JSON number", withToken("12345"), `{"level":"debug","count":12345,"message":"ok"}`, []string{"count=***", "ok"}, []string{"12345"}},
		{"token inside a message", withToken("12345"), `{"message":"session id 12345 started"}`, []string{"session id *** started"}, []string{"12345"}},
		{"token as a whole JSON string", withToken("12345"), `{"userId":"12345"}`, []string{"userId=***"}, []string{"12345"}},
		{"token at the start of an array", withToken("12345"), `{"ids":[12345,67890]}`, []string{"67890"}, []string{"12345"}},
		{"token at the end of an array", withToken("12345"), `{"ids":[67890,12345]}`, []string{"67890"}, []string{"12345"}},
		{"token after a decimal point", withToken("12345"), `{"ratio":123.12345}`, []string{"ratio=123.***"}, []string{"12345"}},
		{"token after a minus", withToken("12345"), `{"delta":-12345}`, []string{"delta=-***"}, []string{"12345"}},
		{"token before digits in a string", withToken("12345"), `{"traceId":"1234598765"}`, []string{"traceId=***98765"}, []string{"12345"}},
		{"token in pretty-printed JSON", withToken("12345"), `{"count" : 12345 , "ok" : true}`, []string{"count=***", "ok=true"}, []string{"12345"}},
		{"token after a run of whitespace", withToken("12345"), "{\"count\":\n\t12345,\n\"ok\":true}", []string{"count=***", "ok=true"}, []string{"12345"}},
		{"token before a space and a comma", withToken("12345"), `{"count":12345 ,"ok":true}`, []string{"count=***", "ok=true"}, []string{"12345"}},
		{"token in a padded array", withToken("12345"), `{"ids": [ 12345, 67890 ]}`, []string{"67890"}, []string{"12345"}},
		{"token in prose in a string", withToken("12345"), `{"msg":"reason: 12345, retry: token"}`, []string{"reason: ***, retry: token"}, []string{"12345"}},
		{"token after an escaped quote", withToken("12345"), `{"note":"a\"count:12345,done"}`, []string{`count:***,done`}, []string{"12345"}},
		{"token twice", withToken("12345"), `{"a":"has 12345 inside","b":12345}`, []string{"has *** inside", "b=***"}, []string{"12345"}},
		{"token after an escaped backslash", withToken("12345"), `{"path":"C:\\","count":12345}`, []string{`path="C:\\"`, "count=***"}, []string{"12345"}},
		{"token after an escaped newline", withToken("12345"), `{"a":"path\nnext","count":12345}`, []string{"path", "next", "count=***"}, []string{"12345"}},
		{"token next to another number", withToken("8080"), `{"port":8080,"timeout":3000}`, []string{"port=***", "timeout=3000"}, []string{"8080"}},
		{"token inside true", withToken("rue"), `{"enabled":true}`, []string{"enabled=true"}, nil},
		{"token inside false", withToken("als"), `{"enabled":false}`, []string{"enabled=false"}, nil},
		{"token inside null", withToken("ull"), `{"value":null}`, []string{"value=null"}, nil},
		{"short token inside a number", withToken("1234"), `{"level":"info","x":12345678,"message":"call with 1234 now"}`, []string{"call with *** now"}, []string{"call with 1234"}},
		{"token with an escaped letter", withToken(secret), `{"m":"s3cr3t\u0076alue99"}`, []string{"m=***"}, []string{secret}},

		{"device token", withValue(machinecredential.CONFIG_KEY_DEVICE_TOKEN, "sdt_example-device-token-value"), `{"level":"info","message":"enrolling with sdt_example-device-token-value now"}`, []string{"enrolling with *** now"}, []string{"sdt_example-device-token-value"}},
		{"short fleet key", withValue(machinecredential.CONFIG_KEY_FLEET_KEY, "a"), `{"level":"info","message":"a banana"}`, []string{"a banana"}, nil},
		{"empty configuration", func(configuration.Configuration) {}, `{"level":"info","message":"seen plain-text here"}`, []string{"seen plain-text here"}, nil},
		{"every kind of secret", configureAllSecrets, allSecretsEvent, []string{"internal-names", "plain text"}, allSecrets},

		{"short flags", nil, `{"level":"debug","args":"-u john.doe -p hunter2","org":"acme","ok":true}`, []string{`args="-u *** -p ***"`, "org=acme", "ok=true"}, []string{"john.doe", "hunter2"}},
		{"short user field", nil, `{"u": "john.doe", "next": "keepme", "arr": [1,2]}`, []string{"u=***", "next=keepme", "arr=[1,2]"}, []string{"john.doe"}},
		{"null password", nil, `{"p":null,"m":1}`, []string{"p=***", "m=1"}, nil},
		{"password with an exponent", nil, `{"time":"t","p":1.5e3}`, []string{"p=***"}, []string{"1.5e3"}},
		{"object password", nil, `{"p":{"a":1},"m":2}`, []string{"p=***", "m=2"}, nil},
		{"array password", nil, `{"p":[1,2],"m":2}`, []string{"p=***", "m=2"}, nil},
		{"nested short fields", nil, `{"a":{"p":"x"},"u":{"k":1}}`, []string{`a={"p":"***"}`, "u=***"}, nil},
		{"number token field", nil, `{"token":1234567,"m":1}`, []string{"token=***", "m=1"}, []string{"1234567"}},
		{"string password", nil, `{"p":"hunter2","m":1}`, []string{"p=***", "m=1"}, []string{"hunter2"}},
		{"short user with an escaped quote in a message", nil, `{"message":"u: a\"b"}`, []string{"u: ***"}, []string{`a"b`}},
		{"password that is a comma", nil, `{"level":"debug","password":",","message":"a,b,c"}`, []string{"password=***", "a,b,c"}, nil},
		{"escaped letters without a credential", nil, `{"m":"caf\u00e9 \u003cok\u003e"}`, []string{"café <ok>"}, nil},
		{"credential after an escaped letter", nil, `{"m":"\u0042earer abcdefghij1"}`, []string{"Bearer ***"}, []string{"abcdefghij1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configuration.NewInMemory()
			out := &bytes.Buffer{}
			writer := logging.NewConsoleWriter(out, func() configuration.Configuration { return config }, noColor)
			if tt.configure != nil {
				tt.configure(config)
			}

			_, err := writer.Write([]byte(tt.event))

			require.NoError(t, err)
			for _, shown := range tt.shown {
				assert.Contains(t, out.String(), shown)
			}
			for _, absent := range tt.absent {
				assert.NotContains(t, out.String(), absent)
			}
		})
	}
}

func everyKindOfSecret(t *testing.T) (secrets []string, event string, configure func(configuration.Configuration)) {
	t.Helper()
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	keyPEM, err := machineenrollment.EncodeKeyPEM(key)
	require.NoError(t, err)
	storedJSON, err := json.Marshal(map[string]string{"client_id": "machine-client-id", "private_key_pem": string(keyPEM)})
	require.NoError(t, err)
	pemBody := strings.Split(strings.TrimSpace(string(keyPEM)), "\n")[1]
	fleetKey := base64.StdEncoding.EncodeToString([]byte("example-fleet-key-value"))

	secrets = []string{
		"auth-token+value", "bearer-token-value", "client-secret-value", "client-id-value", "sdt_example-device-token-value",
		fleetKey, pemBody, "oauth-access-value-1", "oauth-refresh-value-2",
	}
	message := strings.Join(append(append([]string{}, secrets...), "internal-name", "internal-names", "plain text"), " | ")
	encoded, err := json.Marshal(map[string]string{"level": "info", "message": message})
	require.NoError(t, err)
	configure = func(config configuration.Configuration) {
		config.Set(configuration.AUTHENTICATION_TOKEN, "auth-token+value")
		config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "bearer-token-value")
		config.Set(auth.PARAMETER_CLIENT_SECRET, "client-secret-value")
		config.Set(auth.PARAMETER_CLIENT_ID, "client-id-value")
		config.Set(machinecredential.CONFIG_KEY_DEVICE_TOKEN, "sdt_example-device-token-value")
		config.Set(machinecredential.CONFIG_KEY_FLEET_KEY, fleetKey)
		config.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, string(storedJSON))
		config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"oauth-access-value-1","refresh_token":"oauth-refresh-value-2"}`)
		config.Set(logging.REDACTION_TERMS, []string{"internal-name"})
	}
	return append(secrets, "internal-name |"), string(encoded), configure
}

func TestConsoleWriter_ShowsAnEventWithoutCredentialsLikeAPlainConsoleWriter(t *testing.T) {
	event := "{ \"level\" : \"debug\",\n\t\"ratio\":1.50e+03, \"zero\":-0.0, \"big\":12345678901234567890,\"ok\":true,\"none\":null," +
		`"path":"C:\\dir\/file","text":"caf\u00e9","list":[ 1 , "two" ],"message":"cache hit"}` + "\n"
	plain := &bytes.Buffer{}
	_, err := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) { w.Out = plain }, noColor).Write([]byte(event))
	require.NoError(t, err)
	redacted := &bytes.Buffer{}
	config := configuration.NewInMemory()

	_, err = logging.NewConsoleWriter(redacted, func() configuration.Configuration { return config }, noColor).Write([]byte(event))

	require.NoError(t, err)
	assert.Equal(t, plain.String(), redacted.String())
	for _, shown := range []string{"ratio=1.50e+03", "zero=-0.0", "big=12345678901234567890", "ok=true", `list=[1,"two"]`, "cache hit"} {
		assert.Contains(t, redacted.String(), shown)
	}
}

func BenchmarkConsoleWriter_Event(b *testing.B) {
	config := configuration.NewInMemory()
	config.Set(configuration.AUTHENTICATION_TOKEN, fakeAPIToken())
	config.Set(logging.REDACTION_TERMS, []string{"Content", "reference", "command"})
	event := []byte(`{"level":"debug","ext":"main","separator":"-","method":"GET","url":"https://api.example.com/rest/orgs?version=2024-10-15","status":200,"durationMs":123,"time":"2026-11-16T12:00:00Z","message":"< Content-Type: application/json"}` + "\n")
	writer := logging.NewConsoleWriter(&bytes.Buffer{}, func() configuration.Configuration { return config }, noColor)
	for b.Loop() {
		if _, err := writer.Write(event); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConsoleWriter_EventWithEmbeddedJSONBody(b *testing.B) {
	pairs := make([]string, 500)
	for i := range pairs {
		pairs[i] = fmt.Sprintf(`\"field%d\":\"value%d\"`, i, i)
	}
	event := []byte(`{"level":"debug","message":"< body: {` + strings.Join(pairs, ",") + `}"}` + "\n")
	config := configuration.NewInMemory()
	writer := logging.NewConsoleWriter(&bytes.Buffer{}, func() configuration.Configuration { return config }, noColor)
	for b.Loop() {
		if _, err := writer.Write(event); err != nil {
			b.Fatal(err)
		}
	}
}

func TestConsoleWriter_ReadsTheConfigurationOncePerEvent(t *testing.T) {
	config := configuration.NewInMemory()
	var reads atomic.Int32
	config.AddDefaultValue(logging.REDACTION_TERMS, func(_ configuration.Configuration, existing interface{}) (interface{}, error) {
		reads.Add(1)
		return existing, nil
	})
	logger := zerolog.New(logging.NewConsoleWriter(&bytes.Buffer{}, func() configuration.Configuration { return config }, noColor))

	logger.Info().Str("a", "x").Str("b", "y").Strs("c", []string{"1", "2"}).Msg("first")
	logger.Info().Str("a", "x").Msg("second")

	assert.Equal(t, int32(2), reads.Load())
}
