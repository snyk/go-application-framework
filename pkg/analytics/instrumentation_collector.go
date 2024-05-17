package analytics

import (
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
	SetCmdArguments(args []string)
	SetUserAgent(ua networking.UserAgentInfo)
	SetInteractionId(id string)
	SetTimestamp(t time.Time)
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
	args                []string
	userAgent           networking.UserAgentInfo
	interactionId       string
	timestamp           time.Time
	stage               string
	instrumentationType string
	category            []string // TODO: switch to using enum?
	status              Status
	testSummary         json_schemas.TestSummary
	targetId            string // TODO: switch to using purl lib?
	instrumentationErr  error
	extension           map[string]string
}

func (ic *instrumentationCollectorImpl) SetCmdArguments(args []string) {
	ic.args = args
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

// TODO: this should return a payload(?) that matches the V2 instrumentation schema of the analytics service
//func GetV2Instrumentation(c InstrumentationCollector) json_schemas.AnalyticsV2Request {
//
//}
