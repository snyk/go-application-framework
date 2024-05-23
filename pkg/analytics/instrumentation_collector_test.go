package analytics

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	api "github.com/snyk/go-application-framework/internal/api/clients"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/networking"
)

func Test_InstrumentationCollector(t *testing.T) {
	ic := newTestInstrumentation(t)

	mockUserAgent := networking.UserAgentInfo{
		App:        "snyk-ls",
		AppVersion: "v20240515.190857",
	}
	mockInteractionId := "interactionID"
	mockTimestamp := time.Now()
	mockStage := "cicd"
	mockInstrumentationType := "analytics"
	mockCategory := []string{"code", "test"}
	mockStatus := Success
	mockTestSummary := json_schemas.NewTestSummary("sast")
	mockTargetId := "targetID"
	mockExtension := map[string]interface{}{"strings": "hello world"}

	ic.SetUserAgent(mockUserAgent)
	ic.SetInteractionId(mockInteractionId)
	ic.SetTimestamp(mockTimestamp)
	ic.SetStage(mockStage)
	ic.SetType(mockInstrumentationType)
	ic.SetCategory(mockCategory)
	ic.SetStatus(mockStatus)
	ic.SetTestSummary(*mockTestSummary)
	ic.SetTargetId(mockTargetId)
	ic.AddExtension("strings", "hello world")

	stage := toInteractionStage(mockStage)
	expectedV2InstrumentationObject := api.AnalyticsRequestBody{
		Data: api.AnalyticsData{
			Type: mockInstrumentationType,
			Attributes: api.AnalyticsAttributes{
				Interaction: api.Interaction{
					Categories:  &mockCategory,
					Errors:      &[]api.InteractionError{},
					Extension:   &mockExtension,
					Id:          mockInteractionId,
					Results:     toInteractionResults(mockTestSummary),
					Stage:       &stage,
					Status:      string(mockStatus),
					Target:      api.Target{Id: mockTargetId},
					TimestampMs: mockTimestamp.UnixMilli(),
					Type:        mockInstrumentationType,
				},
				Runtime: &api.Runtime{
					Application: &api.Application{
						Name:    mockUserAgent.App,
						Version: mockUserAgent.AppVersion,
					},
				},
			},
		},
	}

	t.Run("it should construct a V2 instrumentation object", func(t *testing.T) {
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		assert.Equal(t, expectedV2InstrumentationObject, *actualV2InstrumentationObject)
	})

	t.Run("it sets the userAgent environment data", func(t *testing.T) {
		mockUserAgent.IntegrationEnvironment = "VScode"
		mockUserAgent.IntegrationEnvironmentVersion = "1.89"

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Environment = &api.Environment{
			Name:    mockUserAgent.IntegrationEnvironment,
			Version: mockUserAgent.IntegrationEnvironmentVersion,
		}

		ic.SetUserAgent(mockUserAgent)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		assert.Equal(t, expectedV2InstrumentationObject, *actualV2InstrumentationObject)
	})

	t.Run("it sets the userAgent integration data", func(t *testing.T) {
		mockUserAgent.Integration = "Snyk Security plugin for VSCode"
		mockUserAgent.IntegrationVersion = "v2.70"

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Integration = &api.Integration{
			Name:    mockUserAgent.Integration,
			Version: mockUserAgent.IntegrationVersion,
		}

		ic.SetUserAgent(mockUserAgent)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		assert.Equal(t, expectedV2InstrumentationObject, *actualV2InstrumentationObject)
	})

	t.Run("it sets the userAgent platform data", func(t *testing.T) {
		mockUserAgent.OS = "macos"
		mockUserAgent.Arch = "arm64"

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Platform = &api.Platform{
			Os:   mockUserAgent.OS,
			Arch: mockUserAgent.Arch,
		}

		ic.SetUserAgent(mockUserAgent)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		assert.Equal(t, expectedV2InstrumentationObject, *actualV2InstrumentationObject)
	})

	t.Run("it sets the userAgent performance data", func(t *testing.T) {
		mockDuration := 10 * time.Millisecond

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Performance = &api.Performance{
			DurationMs: mockDuration.Milliseconds(),
		}

		ic.SetDuration(mockDuration)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		assert.Equal(t, expectedV2InstrumentationObject, *actualV2InstrumentationObject)
	})

	t.Run("it should collect interaction errors", func(t *testing.T) {
		mockError := fmt.Errorf("oops")
		ic.AddError(mockError)

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Errors = toInteractionErrors([]error{mockError})

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		assert.Equal(t, expectedV2InstrumentationObject, *actualV2InstrumentationObject)
	})

	t.Run("it should support all interaction extension types", func(t *testing.T) {
		ic.AddExtension("integers", 123)
		ic.AddExtension("booleans", true)

		mockExtension = map[string]interface{}{
			"strings":  "hello world",
			"integers": 123,
			"booleans": true,
		}

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = &mockExtension

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		assert.Equal(t, expectedV2InstrumentationObject, *actualV2InstrumentationObject)
	})

	t.Run("it should return error when runtime application data is missing", func(t *testing.T) {
		mockUserAgent = networking.UserAgentInfo{}
		ic.SetUserAgent(mockUserAgent)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)

		expectedErr := errors.New("no user agent application data")

		assert.Nil(t, actualV2InstrumentationObject)
		assert.Error(t, expectedErr, err)
	})
}

func newTestInstrumentation(t *testing.T) InstrumentationCollector {
	t.Helper()
	a := NewInstrumentationCollector()
	return a
}
