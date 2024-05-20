package analytics

import (
	api "github.com/snyk/go-application-framework/pkg/analytics/2024-03-07"
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

	t.Run("it should construct a V2 instrumentation object", func(t *testing.T) {
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

		expectedV2InstrumentationObject := api.AnalyticsRequestBody{
			Data: api.AnalyticsData{
				Type: mockInstrumentationType,
				Attributes: api.AnalyticsAttributes{
					Interaction: api.Interaction{
						Categories:  &mockCategory,
						Errors:      &[]api.InteractionError{},
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

		actualV2InstrumentationObject := GetV2InstrumentationObject(ic)

		assert.Equal(t, &expectedV2InstrumentationObject, actualV2InstrumentationObject)
	})
}

func newTestInstrumentation(t *testing.T) InstrumentationCollector {
	t.Helper()
	a := NewInstrumentationCollector()
	return a
}
