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

package networking_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/networking"
)

// Fake credentials are assembled at runtime so that secret scanners don't flag the test sources.
func fakeToken(n int) string {
	return strings.Join([]string{"3f9c2b7e", "41d8", "4a6b", "9e2f", fmt.Sprintf("0c5d8a1b7e6%d", n)}, "-")
}

func TestTraceLog_CredentialsOfRequestsNeverShow(t *testing.T) {
	sessionCookie := strings.Repeat("c00k1e", 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: sessionCookie, HttpOnly: true, Secure: true})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fields := strings.Fields(r.Header.Get("Authorization"))
		require.Len(t, fields, 2, "the request is authenticated")
		_, err := fmt.Fprintf(w, "you sent %s", fields[1])
		assert.NoError(t, err)
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_TOKEN, fakeToken(1))
	out := &bytes.Buffer{}
	logger := zerolog.New(logging.NewConsoleWriter(out, func() configuration.Configuration { return config }, func(w *zerolog.ConsoleWriter) { w.NoColor = true })).Level(zerolog.TraceLevel)
	network := networking.NewNetworkAccess(config)
	network.SetLogger(&logger)

	get := func() {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/rest/self", nil)
		require.NoError(t, err)
		request.Header.Set("Cookie", "session="+sessionCookie)
		response, err := network.GetHttpClient().Do(request)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
	}
	get()
	config.Set(configuration.AUTHENTICATION_TOKEN, fakeToken(2))
	get()

	shown := out.String()
	assert.Equal(t, 2, strings.Count(shown, "you sent ***"), "both responses are logged")
	assert.Contains(t, shown, "Authorization:[***]")
	assert.Contains(t, shown, "Cookie:[***]")
	assert.Contains(t, shown, "Set-Cookie:[***]")
	assert.NotContains(t, shown, fakeToken(1))
	assert.NotContains(t, shown, fakeToken(2))
	assert.NotContains(t, shown, sessionCookie)
}
