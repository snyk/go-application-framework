package contributorbilling_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestEmitContributorBilling_Integration_AppliesConfigurationAndPosts(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL+"/v1")
	config.Set(configuration.AUTHENTICATION_TOKEN, "integration-token")
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, false)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	require.NoError(t, engine.Init())
	emitter := contributorbilling.NewEmitter()
	wait := contributorbilling.WaitBudget(1, contributorbilling.DefaultTimeout)
	defer emitter.WaitWithTimeout(wait)

	opts := contributorbilling.EmitOptions{
		Configuration: config,
		Engine:        engine,
		Capability:    contributorbilling.CapabilityOSS,
		ScopeID:       "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: "22222222-2222-2222-2222-222222222222"},
		},
	}
	contributorbilling.ApplyFromConfiguration(&opts, config, engine)
	opts.HTTPClient = server.Client()

	resultCh := make(chan contributorbilling.Result, 1)
	opts.OnResult = func(result contributorbilling.Result) {
		resultCh <- result
	}
	emitter.EmitContributorBilling(context.Background(), opts)

	require.True(t, emitter.WaitWithTimeout(wait))

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.Equal(t, "token integration-token", gotAuth)
}
