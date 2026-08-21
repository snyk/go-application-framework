package contributorbilling

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestApplyFromConfiguration_FillsUnsetNetworkFields(t *testing.T) {
	t.Parallel()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.test")
	config.Set(configuration.AUTHENTICATION_TOKEN, "secret-token")

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	require.NoError(t, engine.Init())

	opts := EmitOptions{
		ScopeID:       "11111111-1111-1111-1111-111111111111",
		Configuration: config,
		Engine:        engine,
	}

	ApplyFromConfiguration(&opts, config, engine)

	require.NotNil(t, opts.HTTPClient)
	assert.Equal(t, "https://api.example.test", opts.IngestURL)
	assert.Equal(t, auth.GetAuthHeader(config), opts.AuthHeader)
}

func TestApplyFromConfiguration_PreservesExplicitOverrides(t *testing.T) {
	t.Parallel()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.test")
	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	require.NoError(t, engine.Init())

	explicitClient := engine.GetNetworkAccess().GetHttpClient()
	opts := EmitOptions{
		HTTPClient:    explicitClient,
		IngestURL:     "https://override.example.test/v1",
		AuthHeader:    "token override",
		Configuration: config,
		Engine:        engine,
	}

	ApplyFromConfiguration(&opts, config, engine)

	assert.Same(t, explicitClient, opts.HTTPClient)
	assert.Equal(t, "https://override.example.test/v1", opts.IngestURL)
	assert.Equal(t, "token override", opts.AuthHeader)
}
