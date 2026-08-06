package contributorbilling_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling"
	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestEmitContributorBilling_Integration_AppliesConfigurationAndPosts(t *testing.T) {
	t.Parallel()

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL+"/v1")
	config.Set(configuration.AUTHENTICATION_TOKEN, "integration-token")

	engine := app.CreateAppEngineWithOptions(app.WithConfiguration(config))
	emitter := contributorbilling.NewEmitter()
	defer emitter.WaitWithTimeout(2 * time.Second)

	resultCh := make(chan contributorbilling.Result, 1)
	emitter.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		Configuration: config,
		Engine:        engine,
		ScopeID:       "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: "22222222-2222-2222-2222-222222222222"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	require.True(t, emitter.WaitWithTimeout(2*time.Second))

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.Equal(t, "token integration-token", gotAuth)
}
