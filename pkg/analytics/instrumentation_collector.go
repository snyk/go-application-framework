package analytics

import (
	v20240307 "github.com/snyk/go-application-framework/pkg/analytics/2024-03-07"
	"time"

	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/networking"
)

const (
	Success Status = "success"
	Failure Status = "failure"
)

type Status string

type InstrumentationCollector interface {
	SetUserAgent(ua networking.UserAgentInfo)
	SetInteractionId(id string)
	SetTimestamp(t time.Time)
	SetDuration(duration time.Duration)
	SetStage(s string)
	SetType(t string)
	SetCategory(c []string)
	SetStatus(s Status)
	SetTestSummary(s json_schemas.TestSummary)
	SetTargetId(t string) // maybe use package-url library and types
	AddError(err error)
	AddExtension(key string, value string)
}

var _ InstrumentationCollector = (*instrumentationCollectorImpl)(nil)

func NewInstrumentationCollector() InstrumentationCollector {
	return &instrumentationCollectorImpl{}
}

type instrumentationCollectorImpl struct {
	userAgent           networking.UserAgentInfo
	interactionId       string
	timestamp           time.Time
	duration            time.Duration
	stage               string
	instrumentationType string
	category            []string // TODO: switch to using enum?
	status              Status
	testSummary         json_schemas.TestSummary
	targetId            string // TODO: switch to using purl lib?
	instrumentationErr  error
	extension           map[string]interface{}
}

func (ic *instrumentationCollectorImpl) SetUserAgent(ua networking.UserAgentInfo) {
	ic.userAgent = ua
}

func (ic *instrumentationCollectorImpl) SetInteractionId(id string) {
	ic.interactionId = id
}

func (ic *instrumentationCollectorImpl) SetTimestamp(t time.Time) {
	ic.timestamp = t
}

func (ic *instrumentationCollectorImpl) SetDuration(d time.Duration) {
	ic.duration = d
}

func (ic *instrumentationCollectorImpl) SetStage(s string) {
	ic.stage = s
}

func (ic *instrumentationCollectorImpl) SetType(t string) {
	ic.instrumentationType = t
}

func (ic *instrumentationCollectorImpl) SetCategory(c []string) {
	ic.category = c
}

func (ic *instrumentationCollectorImpl) SetStatus(s Status) {
	ic.status = s
}

func (ic *instrumentationCollectorImpl) SetTestSummary(s json_schemas.TestSummary) {
	ic.testSummary = s
}

func (ic *instrumentationCollectorImpl) SetTargetId(t string) {
	ic.targetId = t
}

func (ic *instrumentationCollectorImpl) AddError(err error) {
	ic.instrumentationErr = err
}

func (ic *instrumentationCollectorImpl) AddExtension(key string, value string) {
	ic.extension[key] = value
}

func (ic *instrumentationCollectorImpl) GetV2InstrumentationObject() v20240307.AnalyticsRequestBody {
	d := v20240307.AnalyticsData{
		Type:       ic.instrumentationType,
		Attributes: ic.getV2Attributes(),
	}

	return v20240307.AnalyticsRequestBody{
		Data: d,
	}
}

func (ic *instrumentationCollectorImpl) getV2Attributes() v20240307.AnalyticsAttributes {
	return v20240307.AnalyticsAttributes{
		Interaction: ic.getV2Interaction(),
		Runtime:     ic.getV2Runtime(),
	}
}

func (ic *instrumentationCollectorImpl) getV2Interaction() v20240307.Interaction {
	return v20240307.Interaction{
		Id:          ic.interactionId,
		Results:     toInteractionResults(&ic.testSummary),
		Stage:       toInteractionStage(&ic.stage),
		Target:      v20240307.Target{ic.targetId},
		TimestampMs: ic.timestamp.UnixMilli(),
		Type:        ic.instrumentationType,
		Categories:  &ic.category,
		Errors:      nil, // TODO: implement this
	}
}

// TODO: validate these runtime <> userAgent mappings are correct
func (ic *instrumentationCollectorImpl) getV2Runtime() *v20240307.Runtime {
	return &v20240307.Runtime{
		Application: &v20240307.Application{
			Name:    ic.userAgent.App,
			Version: ic.userAgent.AppVersion,
		},
		Environment: &v20240307.Environment{
			Name:    ic.userAgent.IntegrationEnvironment,
			Version: ic.userAgent.IntegrationEnvironmentVersion,
		},
		Integration: &v20240307.Integration{
			Name:    ic.userAgent.Integration,
			Version: ic.userAgent.IntegrationVersion,
		},
		Performance: &v20240307.Performance{
			DurationMs: ic.duration.Milliseconds(),
		},
		Platform: &v20240307.Platform{
			Arch: ic.userAgent.Arch,
			Os:   ic.userAgent.OS,
		},
	}
}

// TODO: validate this is correctly implemented
func toInteractionResults(testSummary *json_schemas.TestSummary) *[]map[string]interface{} {
	r := []map[string]interface{}{}
	for _, result := range testSummary.Results {
		r = append(r, map[string]interface{}{
			"severity": result.Severity,
			"total":    result.Total,
			"open":     result.Open,
			"ignored":  result.Ignored,
		})
	}
	return &r
}

func toInteractionStage(s *string) *v20240307.InteractionStage {
	var is v20240307.InteractionStage

	switch stage := s; *stage {
	case "cicd":
		is = v20240307.Cicd
	case "dev":
		is = v20240307.Dev
	case "prchecks":
		is = v20240307.Prchecks
	default:
		is = v20240307.Unknown
	}

	return &is
}
