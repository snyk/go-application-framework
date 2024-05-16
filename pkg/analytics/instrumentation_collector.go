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

type InstrumentationCollectorImpl struct{}

func (InstrumentationCollectorImpl) SetCmdArguments(args []string) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) SetUserAgent(ua networking.UserAgentInfo) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) SetInteractionId(id string) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) SetTimestamp(t time.Time) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) SetStage(s string) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) SetType(t string) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) SetCategory(c []string) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) SetStatus(s Status) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) SetTestSummary(s json_schemas.TestSummary) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) SetTargetId(t string) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) AddError(err error) {
	//TODO implement me
	panic("implement me")
}

func (InstrumentationCollectorImpl) AddExtension(key string, value string) {
	//TODO implement me
	panic("implement me")
}

//func getV2Instrumentation(c InstrumentationCollector) []byte
