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

var _ InstrumentationCollector = (*InstrumentationCollectorImpl)(nil)

func NewInstrumentationCollector() InstrumentationCollector {
	return &InstrumentationCollectorImpl{}
}

type InstrumentationCollectorImpl struct {
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

func (ic *InstrumentationCollectorImpl) SetCmdArguments(args []string) {
	ic.args = args
}

func (ic *InstrumentationCollectorImpl) SetUserAgent(ua networking.UserAgentInfo) {
	ic.userAgent = ua
}

func (ic *InstrumentationCollectorImpl) SetInteractionId(id string) {
	ic.interactionId = id
}

func (ic *InstrumentationCollectorImpl) SetTimestamp(t time.Time) {
	ic.timestamp = t
}

func (ic *InstrumentationCollectorImpl) SetStage(s string) {
	ic.stage = s
}

func (ic *InstrumentationCollectorImpl) SetType(t string) {
	ic.instrumentationType = t
}

func (ic *InstrumentationCollectorImpl) SetCategory(c []string) {
	ic.category = c
}

func (ic *InstrumentationCollectorImpl) SetStatus(s Status) {
	ic.status = s
}

func (ic *InstrumentationCollectorImpl) SetTestSummary(s json_schemas.TestSummary) {
	ic.testSummary = s
}

func (ic *InstrumentationCollectorImpl) SetTargetId(t string) {
	ic.targetId = t
}

func (ic *InstrumentationCollectorImpl) AddError(err error) {
	ic.instrumentationErr = err
}

func (ic *InstrumentationCollectorImpl) AddExtension(key string, value string) {
	ic.extension[key] = value
}

//func getV2Instrumentation(c InstrumentationCollector) []byte
