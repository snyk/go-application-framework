package analytics

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/stretchr/testify/assert"

	api "github.com/snyk/go-application-framework/internal/api/analytics/2024-03-07"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/networking"
)

var logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

func Test_InstrumentationCollector(t *testing.T) {
	t.Run("it should construct a V2 instrumentation object", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent application data", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockUserAgent := networking.UserAgentInfo{}
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

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent environment data", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockUserAgent := networking.UserAgentInfo{}
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

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent integration data", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockUserAgent := networking.UserAgentInfo{}
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

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent platform data", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockUserAgent := networking.UserAgentInfo{}
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

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent performance data", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

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

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should collect interaction errors", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockError := fmt.Errorf("oops")
		ic.AddError(mockError)

		snykError := snyk.NewBadRequestError("")
		ic.AddError(snykError)

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Errors = toInteractionErrors([]error{mockError, snykError})
		assert.Equal(t, 1, len(*expectedV2InstrumentationObject.Data.Attributes.Interaction.Errors))

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should support all interaction extension types", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		ic.AddExtension("integers", 123)
		ic.AddExtension("booleans", true)

		mockExtension := map[string]interface{}{
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

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should sanitize potential PII data put in the extension type", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		ic.AddExtension("password", "hunter2")

		mockExtension := map[string]interface{}{
			"strings":  "hello world",
			"password": "REDACTED",
		}

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = &mockExtension

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger))
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should exclude datapoint from extension object if type is not valid", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		assert.Panics(t, func() {
			ic.AddExtension("thisIsNotAValidType", []string{"invalid", "type"})
		})

		ic.AddExtension("perfectlyValidInt", 1)
		ic.AddExtension("perfectlyValidBool", true)

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = &map[string]interface{}{
			"strings":            "hello world",
			"perfectlyValidInt":  1,
			"perfectlyValidBool": true,
		}

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger))
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should remove the extension object gracefully if sanitation fails ", func(t *testing.T) {
		ic := setupBaseCollector(t)
		icImpl, ok := ic.(*instrumentationCollectorImpl)
		assert.True(t, ok)
		icImpl.extension = map[string]interface{}{
			"string": "This is a valid string",
			"int":    12345,
			"fail":   func() { fmt.Println("I cause problems for JSON marshaling!") },
		}

		expectedV2InstrumentationObject := buildExpectedBaseObject(t)
		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = nil

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(icImpl, WithLogger(&logger))
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should get the category vector", func(t *testing.T) {
		ic := setupBaseCollector(t)

		mockCategory := []string{"code", "test"}
		actualCategory := ic.GetCategory()
		assert.Equal(t, mockCategory, actualCategory)
	})
}

func setupBaseCollector(t *testing.T) InstrumentationCollector {
	t.Helper()

	ic := NewInstrumentationCollector()
	ic.SetInteractionId("interactionID")
	ic.SetTimestamp(time.Now())
	ic.SetStage("cicd")
	ic.SetType("analytics")
	ic.SetInteractionType("Scan done")
	ic.SetCategory([]string{"code", "test"})
	ic.SetStatus(Success)
	ic.SetTestSummary(*json_schemas.NewTestSummary("sast", ""))
	ic.SetTargetId("targetID")
	ic.AddExtension("strings", "hello world")
	ic.SetTimestamp(time.Date(2025, 1, 01, 0, 0, 0, 0, time.UTC))

	return ic
}

// Helper function to build the expected response object
func buildExpectedBaseObject(t *testing.T) api.AnalyticsRequestBody {
	t.Helper()

	mockInteractionId := "interactionID"
	mockStage := "cicd"
	mockInstrumentationType := "analytics"
	mockInteractionType := "Scan done"
	mockCategory := []string{"code", "test"}
	mockStatus := Success
	mockTestSummary := json_schemas.NewTestSummary("sast", "")
	mockTargetId := "targetID"
	mockExtension := map[string]interface{}{"strings": "hello world"}

	stage := toInteractionStage(mockStage)
	expected := api.AnalyticsRequestBody{
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
					TimestampMs: time.Date(2025, 1, 01, 0, 0, 0, 0, time.UTC).UnixMilli(),
					Type:        mockInteractionType,
				},
				Runtime: &api.Runtime{},
			},
		},
	}

	return expected
}
