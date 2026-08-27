package analytics

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/snyk/go-application-framework/pkg/logging"
	"maps"
	"os/user"
	"reflect"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	api "github.com/snyk/go-application-framework/internal/api/analytics/2024-03-07"
	"github.com/snyk/go-application-framework/pkg/configuration"
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
	extensionMu         sync.Mutex
	extension           map[string]interface{}
}

type serializeOptions struct {
	logger *zerolog.Logger
	cfg    configuration.Configuration
}

type serializeOptionFunc func(*serializeOptions)

func WithLogger(logger *zerolog.Logger) serializeOptionFunc {
	return func(o *serializeOptions) {
		o.logger = logger
	}
}

// WithConfiguration opts sanitizeExtensionData into shape-based secret redaction,
// using the same scrub dictionary GAF's debug-log redaction already trusts.
// Omitted, sanitizeExtensionData's behavior is unchanged from before this option existed.
func WithConfiguration(cfg configuration.Configuration) serializeOptionFunc {
	return func(o *serializeOptions) {
		o.cfg = cfg
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
	ic.extensionMu.Lock()
	defer ic.extensionMu.Unlock()
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

	return t.getV2InstrumentationObject(&options), nil
}

func (ic *instrumentationCollectorImpl) getV2InstrumentationObject(options *serializeOptions) *api.AnalyticsRequestBody {
	a := ic.getV2Attributes()

	d := api.AnalyticsData{
		Type:       ic.instrumentationType,
		Attributes: a,
	}

	return ic.sanitizeExtensionData(options, d)
}

// Since the `extension` attribute in the analytics payload is a value any
// product line potentially can contribute to, we utilize the same sanitation logic
// already in place for the legacy v1 analytics, to ensure the same level of PII protection.
func (ic *instrumentationCollectorImpl) sanitizeExtensionData(options *serializeOptions, d api.AnalyticsData) *api.AnalyticsRequestBody {
	logger := options.logger

	// Scrub string leaf values before marshaling, never the marshaled JSON bytes: logging.ScrubValue
	// does whole-string literal replacement, so running it over raw JSON would let a redacted
	// value collide with an unrelated field that happens to contain the same substring.
	if options.cfg != nil && d.Attributes.Interaction.Extension != nil {
		scrubbed := scrubExtensionMap(*d.Attributes.Interaction.Extension, logging.GetScrubDictFromConfig(options.cfg))
		d.Attributes.Interaction.Extension = &scrubbed
	}

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
	sanitized, err = SanitizeValuesByKey(logging.SENSITIVE_FIELD_NAMES, logging.SANITIZE_REPLACEMENT_STRING, extension)
	if err != nil {
		logger.Printf("failed to sanitize extension, removing object from analytics payload as sanitzation was not possible: %v", err)
		return result
	}

	u, err := user.Current()
	if err != nil {
		logger.Printf("failed to find user information while sanitizing extension payload, removing object from analytics payload as sanitzation was not possible: %v", err)
		return result
	}

	sanitized, err = SanitizeUsername(u.Username, u.HomeDir, logging.SANITIZE_REPLACEMENT_STRING, sanitized)
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

// scrubExtensionMap and scrubExtensionValue redact string leaves of an arbitrary
// AddExtension payload without ever serializing it to JSON bytes first, so a redaction
// can't run past the field it matched in and corrupt or bleed into a sibling field.
func scrubExtensionMap(m map[string]interface{}, dict logging.ScrubbingDict) map[string]interface{} {
	return scrubExtensionMapSeen(m, dict, map[uintptr]bool{})
}

// seen tracks map/slice pointers on the current recursion path, guarding against
// cycles a caller of AddExtension could construct (e.g. a map containing itself).
// It is deleted on the way back up so a value referenced from two non-cyclic
// branches (a diamond, not a cycle) is still scrubbed both times.
func scrubExtensionMapSeen(m map[string]interface{}, dict logging.ScrubbingDict, seen map[uintptr]bool) map[string]interface{} {
	ptr := reflect.ValueOf(m).Pointer()
	if seen[ptr] {
		return nil
	}
	seen[ptr] = true
	defer delete(seen, ptr)

	scrubbed := make(map[string]interface{}, len(m))
	for k, v := range m {
		scrubbed[k] = scrubExtensionValueSeen(v, dict, seen)
	}
	return scrubbed
}

func scrubExtensionValueSeen(v interface{}, dict logging.ScrubbingDict, seen map[uintptr]bool) interface{} {
	switch val := v.(type) {
	case string:
		return string(logging.ScrubValue([]byte(val), dict))
	case map[string]interface{}:
		return scrubExtensionMapSeen(val, dict, seen)
	case []interface{}:
		ptr := reflect.ValueOf(val).Pointer()
		if ptr != 0 && seen[ptr] {
			return nil
		}
		if ptr != 0 {
			seen[ptr] = true
			defer delete(seen, ptr)
		}
		scrubbed := make([]interface{}, len(val))
		for i, item := range val {
			scrubbed[i] = scrubExtensionValueSeen(item, dict, seen)
		}
		return scrubbed
	default:
		return v
	}
}

func (ic *instrumentationCollectorImpl) getV2Attributes() api.AnalyticsAttributes {
	r := ic.getV2Runtime()

	return api.AnalyticsAttributes{
		Interaction: ic.getV2Interaction(),
		Runtime:     r,
	}
}

func (ic *instrumentationCollectorImpl) getV2Interaction() api.Interaction {
	ic.extensionMu.Lock()
	extensionCopy := maps.Clone(ic.extension)
	ic.extensionMu.Unlock()

	stage := toInteractionStage(ic.stage)
	return api.Interaction{
		Categories:  &ic.category,
		Errors:      toInteractionErrors(ic.instrumentationErr),
		Extension:   &extensionCopy,
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
