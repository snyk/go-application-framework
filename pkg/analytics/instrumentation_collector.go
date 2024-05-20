package analytics

import (
	"errors"
	"fmt"
	"time"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	api "github.com/snyk/go-application-framework/internal/clients"

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
	instrumentationErr  []error
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
	ic.instrumentationErr = append(ic.instrumentationErr, err)
}

func (ic *instrumentationCollectorImpl) AddExtension(key string, value string) {
	ic.extension[key] = value
}

func GetV2InstrumentationObject(collector InstrumentationCollector) *api.AnalyticsRequestBody {
	t, ok := collector.(*instrumentationCollectorImpl)
	if ok {
		return t.GetV2InstrumentationObject()
	}
	return nil
}

func (ic *instrumentationCollectorImpl) GetV2InstrumentationObject() *api.AnalyticsRequestBody {
	d := api.AnalyticsData{
		Type:       ic.instrumentationType,
		Attributes: ic.getV2Attributes(),
	}

	return &api.AnalyticsRequestBody{
		Data: d,
	}
}

func (ic *instrumentationCollectorImpl) getV2Attributes() api.AnalyticsAttributes {
	return api.AnalyticsAttributes{
		Interaction: ic.getV2Interaction(),
		Runtime:     ic.getV2Runtime(),
	}
}

func (ic *instrumentationCollectorImpl) getV2Interaction() api.Interaction {
	return api.Interaction{
		Id:          ic.interactionId,
		Results:     toInteractionResults(&ic.testSummary),
		Stage:       toInteractionStage(&ic.stage),
		Target:      api.Target{Id: ic.targetId},
		TimestampMs: ic.timestamp.UnixMilli(),
		Type:        ic.instrumentationType,
		Categories:  &ic.category,
		Errors:      toInteractionErrors(ic.instrumentationErr),
		Status:      string(ic.status),
	}
}

func (ic *instrumentationCollectorImpl) getV2Runtime() *api.Runtime {
	return &api.Runtime{
		Application: &api.Application{
			Name:    ic.userAgent.App,
			Version: ic.userAgent.AppVersion,
		},
		Environment: &api.Environment{
			Name:    ic.userAgent.IntegrationEnvironment,
			Version: ic.userAgent.IntegrationEnvironmentVersion,
		},
		Integration: &api.Integration{
			Name:    ic.userAgent.Integration,
			Version: ic.userAgent.IntegrationVersion,
		},
		Performance: &api.Performance{
			DurationMs: ic.duration.Milliseconds(),
		},
		Platform: &api.Platform{
			Arch: ic.userAgent.Arch,
			Os:   ic.userAgent.OS,
		},
	}
}

func toInteractionResults(testSummary *json_schemas.TestSummary) *[]map[string]interface{} {
	r := []map[string]interface{}{}
	for _, result := range testSummary.Results {
		r = append(r, map[string]interface{}{
			"name":  result.Severity,
			"count": result.Total,
		})
	}
	return &r
}

func toInteractionStage(s *string) *api.InteractionStage {
	var is api.InteractionStage

	switch stage := s; *stage {
	case "cicd":
		is = api.Cicd
	case "dev":
		is = api.Dev
	case "prchecks":
		is = api.Prchecks
	default:
		is = api.Unknown
	}

	return &is
}

func toInteractionErrors(errors []error) *[]api.InteractionError {
	interactionErrors := []api.InteractionError{}
	for _, e := range errors {
		if interactionError := toInteractionError(e); interactionError != nil {
			interactionErrors = append(interactionErrors, *interactionError)
		}
	}

	return &interactionErrors
}

func toInteractionError(e error) *api.InteractionError {
	errorCatalogError := snyk_errors.Error{}
	var interactionError *api.InteractionError

	if errors.As(e, &errorCatalogError) {
		interactionErrorCode := fmt.Sprintf("%d", errorCatalogError.StatusCode)
		interactionError.Id = errorCatalogError.ErrorCode
		interactionError.Code = &interactionErrorCode
	}

	return interactionError
}
