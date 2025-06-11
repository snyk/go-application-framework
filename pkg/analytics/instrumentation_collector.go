package analytics

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/user"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	api "github.com/snyk/go-application-framework/internal/api/analytics/2024-03-07"
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
	GetDuration() time.Duration
	SetStage(s string)
	SetType(t string)
	SetInteractionType(t string)
	SetCategory(c []string)
	GetCategory() []string
	SetStatus(s Status)
	SetTestSummary(s json_schemas.TestSummary)
	SetTargetId(t string) // maybe use package-url library and types
	AddError(err error)
	// AddExtension adds a new datapoint to the instrumenation's extension property, datapoints must be of type: string, bool, int
	AddExtension(key string, value interface{})
}

var _ InstrumentationCollector = (*instrumentationCollectorImpl)(nil)

func NewInstrumentationCollector() InstrumentationCollector {
	return &instrumentationCollectorImpl{
		extension: make(map[string]interface{}),
	}
}

type instrumentationCollectorImpl struct {
	userAgent           networking.UserAgentInfo
	interactionId       string
	timestamp           time.Time
	duration            time.Duration
	stage               string
	instrumentationType string
	interactionType     string
	category            []string
	status              Status
	testSummary         json_schemas.TestSummary
	targetId            string
	instrumentationErr  []error
	extension           map[string]interface{}
}

type serializeOptions struct {
	logger *zerolog.Logger
}

type serializeOptionFunc func(*serializeOptions)

func WithLogger(logger *zerolog.Logger) serializeOptionFunc {
	return func(o *serializeOptions) {
		o.logger = logger
	}
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
func (ic *instrumentationCollectorImpl) GetDuration() time.Duration {
	return ic.duration
}

func (ic *instrumentationCollectorImpl) SetStage(s string) {
	ic.stage = s
}

func (ic *instrumentationCollectorImpl) SetType(t string) {
	ic.instrumentationType = t
}

func (ic *instrumentationCollectorImpl) SetInteractionType(t string) {
	ic.interactionType = t
}

func (ic *instrumentationCollectorImpl) SetCategory(c []string) {
	ic.category = c
}

func (ic *instrumentationCollectorImpl) GetCategory() []string {
	return ic.category
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

func (ic *instrumentationCollectorImpl) AddExtension(key string, value interface{}) {
	ic.extension[key] = value
}

func GetV2InstrumentationObject(collector InstrumentationCollector, opt ...serializeOptionFunc) (*api.AnalyticsRequestBody, error) {
	t, ok := collector.(*instrumentationCollectorImpl)
	if !ok {
		return nil, fmt.Errorf("failed to convert collector")
	}

	logger := zerolog.Nop()
	options := serializeOptions{
		logger: &logger,
	}
	for _, o := range opt {
		o(&options)
	}

	return t.getV2InstrumentationObject(options.logger), nil
}

func (ic *instrumentationCollectorImpl) getV2InstrumentationObject(logger *zerolog.Logger) *api.AnalyticsRequestBody {
	a := ic.getV2Attributes()

	d := api.AnalyticsData{
		Type:       ic.instrumentationType,
		Attributes: a,
	}

	return ic.sanitizeExtensionData(logger, d)
}

// Since the `extension` attribute in the analytics payload is a value any
// product line potentially can contribute to, we utilize the same sanitation logic
// already in place for the legacy v1 analytics, to ensure the same level of PII protection.
func (ic *instrumentationCollectorImpl) sanitizeExtensionData(logger *zerolog.Logger, d api.AnalyticsData) *api.AnalyticsRequestBody {
	extension, err := json.Marshal(d.Attributes.Interaction.Extension)
	result := &api.AnalyticsRequestBody{
		Data: d,
	}
	result.Data.Attributes.Interaction.Extension = nil

	if err != nil {
		logger.Printf("failed to marshal extension, removing extension object from analytics payload: %v", err)
		return result
	}

	var sanitized []byte
	sanitized, err = SanitizeValuesByKey(sensitiveFieldNames, sanitizeReplacementString, extension)
	if err != nil {
		logger.Printf("failed to sanitize extension, removing object from analytics payload as sanitzation was not possible: %v", err)
		return result
	}

	u, err := user.Current()
	if err != nil {
		logger.Printf("failed to find user information while sanitizing extension payload, removing object from analytics payload as sanitzation was not possible: %v", err)
		return result
	}

	sanitized, err = SanitizeUsername(u.Username, u.HomeDir, sanitizeReplacementString, sanitized)
	if err != nil {
		logger.Printf("failed to sanitize user information in extension payload, removing object from analytics payload as sanitzation was not possible: %v", err)
		return result
	}

	err = json.Unmarshal(sanitized, &result.Data.Attributes.Interaction.Extension)
	if err != nil {
		logger.Printf("failed to unmarshal sanitized extension object:: %v", err)
		return result
	}

	return result
}

func (ic *instrumentationCollectorImpl) getV2Attributes() api.AnalyticsAttributes {
	r := ic.getV2Runtime()

	return api.AnalyticsAttributes{
		Interaction: ic.getV2Interaction(),
		Runtime:     r,
	}
}

func (ic *instrumentationCollectorImpl) getV2Interaction() api.Interaction {
	stage := toInteractionStage(ic.stage)
	return api.Interaction{
		Categories:  &ic.category,
		Errors:      toInteractionErrors(ic.instrumentationErr),
		Extension:   &ic.extension,
		Id:          ic.interactionId,
		Results:     toInteractionResults(&ic.testSummary),
		Stage:       &stage,
		Status:      string(ic.status),
		Target:      api.Target{Id: ic.targetId},
		TimestampMs: ic.timestamp.UnixMilli(),
		Type:        ic.interactionType,
	}
}

func (ic *instrumentationCollectorImpl) getV2Runtime() *api.Runtime {
	var r api.Runtime

	if len(ic.userAgent.App) > 0 {
		r.Application = &api.Application{
			Name:    ic.userAgent.App,
			Version: ic.userAgent.AppVersion,
		}
	}
	if len(ic.userAgent.IntegrationEnvironment) > 0 {
		r.Environment = &api.Environment{
			Name:    ic.userAgent.IntegrationEnvironment,
			Version: ic.userAgent.IntegrationEnvironmentVersion,
		}
	}
	if len(ic.userAgent.Integration) > 0 {
		r.Integration = &api.Integration{
			Name:    ic.userAgent.Integration,
			Version: ic.userAgent.IntegrationVersion,
		}
	}
	if ic.duration.Milliseconds() > 0 {
		r.Performance = &api.Performance{
			DurationMs: ic.duration.Milliseconds(),
		}
	}
	hasUaPlatformData := len(ic.userAgent.Arch) > 0 || len(ic.userAgent.OS) > 0
	if hasUaPlatformData {
		r.Platform = &api.Platform{
			Arch: ic.userAgent.Arch,
			Os:   ic.userAgent.OS,
		}
	}

	return &r
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

func toInteractionStage(s string) api.InteractionStage {
	return api.InteractionStage(s)
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
		interactionError = &api.InteractionError{}
		interactionErrorCode := fmt.Sprintf("%d", errorCatalogError.StatusCode)
		interactionError.Id = errorCatalogError.ErrorCode
		interactionError.Code = &interactionErrorCode
	}

	return interactionError
}
