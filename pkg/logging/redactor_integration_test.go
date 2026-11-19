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
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	keyPEM, err := machineenrollment.EncodeKeyPEM(key)
	require.NoError(t, err)
	storedJSON, err := json.Marshal(map[string]string{"client_id": "machine-client-id", "private_key_pem": string(keyPEM)})
	require.NoError(t, err)
	pemBody := strings.Split(strings.TrimSpace(string(keyPEM)), "\n")[1]
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
		{"machine credential pem line", machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, string(storedJSON), pemBody},
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

func TestRedactor_MachineCredentialIsRedactedInEveryShape(t *testing.T) {
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	keyPEM, err := machineenrollment.EncodeKeyPEM(key)
	require.NoError(t, err)
	storedJSON, err := json.Marshal(map[string]string{"client_id": "machine-client-id", "private_key_pem": string(keyPEM)})
	require.NoError(t, err)
	config := configuration.NewInMemory()
	config.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, string(storedJSON))
	pemBody := strings.Split(strings.TrimSpace(string(keyPEM)), "\n")[1]
	redactor := logging.NewRedactor(func() configuration.Configuration { return config })

	for name, line := range map[string]string{
		"pem as is":        "pem: " + string(keyPEM),
		"stored value":     "value: " + string(storedJSON),
		"one pem line":     "line: " + pemBody,
		"escaped newlines": "value: " + strings.ReplaceAll(string(keyPEM), "\n", `\n`),
	} {
		t.Run(name, func(t *testing.T) {
			assert.NotContains(t, redactor.Redact(line), pemBody)
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
	firstReadStarted, releaseFirstRead := blockFirstReadOfRedactionTerms(config)
	redactor := logging.NewRedactor(func() configuration.Configuration { return config })
	firstRedactionDone := make(chan struct{})
	go func() {
		defer close(firstRedactionDone)
		redactor.Redact("first")
	}()
	<-firstReadStarted

	config.Set(configuration.AUTHENTICATION_TOKEN, "set-during-read-1")
	redacted := redactor.Redact("using set-during-read-1")
	close(releaseFirstRead)
	<-firstRedactionDone

	assert.Equal(t, "using ***", redacted)
}
