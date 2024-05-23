package analytics

import (
	"encoding/json"
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

	mockUserAgent := networking.UserAgentInfo{}
	mockInteractionId := "interactionID"
	mockTimestamp := time.Now()
	mockStage := "cicd"
	mockInstrumentationType := "analytics"
	mockInteractionType := "Scan done"
	mockCategory := []string{"code", "test"}
	mockStatus := Success
	mockTestSummary := json_schemas.NewTestSummary("sast")
	mockTargetId := "targetID"
	mockExtension := map[string]interface{}{"strings": "hello world"}

	ic.SetInteractionId(mockInteractionId)
	ic.SetTimestamp(mockTimestamp)
	ic.SetStage(mockStage)
	ic.SetType(mockInstrumentationType)
	ic.SetInteractionType(mockInteractionType)
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
					Type:        mockInteractionType,
				},
				Runtime: &api.Runtime{},
			},
		},
	}

	t.Run("it should construct a V2 instrumentation object", func(t *testing.T) {
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.Equal(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent application data", func(t *testing.T) {
		mockUserAgent.App = "snyk-ls"
		mockUserAgent.AppVersion = "v20240515.190857"

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Application = &api.Application{
			Name:    mockUserAgent.App,
			Version: mockUserAgent.AppVersion,
		}

		ic.SetUserAgent(mockUserAgent)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.Equal(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
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

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.Equal(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
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

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.Equal(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
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

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.Equal(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent performance data", func(t *testing.T) {
		mockDuration := 10 * time.Millisecond

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Performance = &api.Performance{
			DurationMs: mockDuration.Milliseconds(),
		}

		ic.SetDuration(mockDuration)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.Equal(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should collect interaction errors", func(t *testing.T) {
		mockError := fmt.Errorf("oops")
		ic.AddError(mockError)

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Errors = toInteractionErrors([]error{mockError})

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.Equal(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
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
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.Equal(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})
}

func newTestInstrumentation(t *testing.T) InstrumentationCollector {
	t.Helper()
	a := NewInstrumentationCollector()
	return a
}
