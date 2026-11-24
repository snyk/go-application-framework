package featureflaggateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/mocks"
)

func TestEvaluateFlags_DefaultsVersion_AndPassesBody(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mocks.NewMockClientWithResponsesInterface(ctrl)

	orgID := uuid.New()
	flags := []string{"flag-a", "flag-b"}
	wantBody := buildRequest(flags)

	mockClient.
		EXPECT().
		ListFeatureFlagsWithApplicationVndAPIPlusJSONBodyWithResponse(
			gomock.Any(),
			orgID,
			gomock.Any(),
			wantBody,
		).
		DoAndReturn(func(
			_ context.Context,
			_ v20241015.OrgId,
			params *v20241015.ListFeatureFlagsParams,
			body v20241015.ListFeatureFlagsApplicationVndAPIPlusJSONRequestBody,
			_ ...v20241015.RequestEditorFn,
		) (*v20241015.ListFeatureFlagsResponse, error) {
			if params == nil || params.Version != defaultVersion {
				t.Fatalf("expected Version=%q, got %#v", defaultVersion, params)
			}
			if !reflect.DeepEqual(body, wantBody) {
				t.Fatalf("body mismatch\nwant=%#v\ngot =%#v", wantBody, body)
			}
			return &v20241015.ListFeatureFlagsResponse{}, nil
		})

	withClientFactory(t, func() (v20241015.ClientWithResponsesInterface, error) {
		return mockClient, nil
	})

	resp, err := EvaluateFlags(nil, nil, flags, orgID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestEvaluateFlags_ClientCreationFails(t *testing.T) {
	withClientFactory(t, func() (v20241015.ClientWithResponsesInterface, error) {
		return nil, errors.New("boom")
	})

	_, err := EvaluateFlags(nil, nil, []string{"x"}, uuid.New())
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if got := err.Error(); got != "failed to create feature flag gateway client" {
		t.Fatalf("unexpected error: %q", got)
	}
}

func TestEvaluateFlags_APIRequestFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mocks.NewMockClientWithResponsesInterface(ctrl)

	orgID := uuid.New()
	flags := []string{"flag-a"}

	mockClient.
		EXPECT().
		ListFeatureFlagsWithApplicationVndAPIPlusJSONBodyWithResponse(
			gomock.Any(),
			orgID,
			&v20241015.ListFeatureFlagsParams{Version: defaultVersion},
			buildRequest(flags),
		).
		Return(nil, errors.New("network down"))

	withClientFactory(t, func() (v20241015.ClientWithResponsesInterface, error) {
		return mockClient, nil
	})

	_, err := EvaluateFlags(nil, nil, flags, orgID)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if got := err.Error(); got == "" || !contains(got, "create evaluate flags request") {
		t.Fatalf("expected wrapped error to contain %q, got %q", "create evaluate flags request", got)
	}
}

func withClientFactory(t *testing.T, factory func() (v20241015.ClientWithResponsesInterface, error)) {
	t.Helper()
	orig := newClient
	newClient = func(_ workflow.Engine, _ configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
		return factory()
	}
	t.Cleanup(func() { newClient = orig })
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func Test_newClientImpl_UsesCredentialsAndHostOfTheGivenConfiguration(t *testing.T) {
	const flagsToken = "11111111-2222-4333-8444-555555555555"
	requests := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, writeErr := w.Write([]byte(`{"jsonapi":{"version":"1.0"},"data":{"type":"feature_flags_evaluation","attributes":{"evaluations":[]}}}`))
		assert.NoError(t, writeErr)
	}))
	defer server.Close()

	var engineRequests atomic.Int32
	engineServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		engineRequests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer engineServer.Close()

	// the engine knows another account and another host than the configuration the flags are resolved for
	engineConfig := configuration.NewWithOpts()
	engineConfig.Set(configuration.API_URL, engineServer.URL)
	engineConfig.Set(configuration.AUTHENTICATION_TOKEN, "99999999-8888-4777-8666-555555555555")
	engine := workflow.NewWorkFlowEngine(engineConfig)
	require.NoError(t, engine.Init())

	flagsConfig := engineConfig.Clone()
	flagsConfig.Set(configuration.API_URL, server.URL)
	flagsConfig.Set(configuration.AUTHENTICATION_TOKEN, flagsToken)

	_, err := EvaluateFlags(flagsConfig, engine, []string{"flag"}, uuid.New())
	require.NoError(t, err)

	request := <-requests
	assert.Equal(t, "token "+flagsToken, request.Header.Get("Authorization"), "the token of the configuration the flags are resolved for is used")
	assert.Zero(t, engineRequests.Load(), "the host of the engine is not used")
}
