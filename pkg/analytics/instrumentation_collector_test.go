package analytics

import (
	"errors"
	"fmt"
	api "github.com/snyk/go-application-framework/pkg/analytics/clients"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_InstrumentationCollector(t *testing.T) {
	ic := newTestInstrumentation(t)

	mockUserAgent := networking.UserAgentInfo{
		App:                           "snyk-ls",
		AppVersion:                    "v20240515.190857",
		Integration:                   "VSCode",
		IntegrationVersion:            "v2.70",
		IntegrationEnvironmentVersion: "1.89",
		OS:                            "macos",
		Arch:                          "arm64",
	}
	mockInteractionId := "interactionID"
	mockTimestamp := time.Now()
	mockDuration := time.Duration(1000)
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
	ic.SetDuration(mockDuration)
	ic.SetStage(mockStage)
	ic.SetType(mockInstrumentationType)
	ic.SetCategory(mockCategory)
	ic.SetStatus(mockStatus)
	ic.SetTestSummary(*mockTestSummary)
	ic.SetTargetId(mockTargetId)
	ic.AddExtension("strings", "hello world")

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
					Stage:       toInteractionStage(&mockStage),
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
					Environment: &api.Environment{
						Name:    mockUserAgent.IntegrationEnvironment,
						Version: mockUserAgent.IntegrationEnvironmentVersion,
					},
					Integration: &api.Integration{
						Name:    mockUserAgent.Integration,
						Version: mockUserAgent.IntegrationVersion,
					},
					Performance: &api.Performance{
						DurationMs: mockDuration.Milliseconds(),
					},
					Platform: &api.Platform{
						Arch: mockUserAgent.Arch,
						Os:   mockUserAgent.OS,
					},
				},
			},
		},
	}

	t.Run("it should construct a V2 instrumentation object", func(t *testing.T) {
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)

		assert.Nil(t, err)
		assert.Equal(t, expectedV2InstrumentationObject, *actualV2InstrumentationObject)
	})

	t.Run("it should collect interaction errors", func(t *testing.T) {
		mockError := fmt.Errorf("oops")
		ic.AddError(mockError)

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Errors = toInteractionErrors([]error{mockError})

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)

		assert.Nil(t, err)
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

		assert.Nil(t, err)
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
