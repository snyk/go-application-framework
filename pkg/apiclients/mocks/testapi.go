// Code generated by MockGen. DO NOT EDIT.
// Source: testapi.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	uuid "github.com/google/uuid"
	testapi "github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// MockTestResult is a mock of TestResult interface.
type MockTestResult struct {
	ctrl     *gomock.Controller
	recorder *MockTestResultMockRecorder
}

// MockTestResultMockRecorder is the mock recorder for MockTestResult.
type MockTestResultMockRecorder struct {
	mock *MockTestResult
}

// NewMockTestResult creates a new mock instance.
func NewMockTestResult(ctrl *gomock.Controller) *MockTestResult {
	mock := &MockTestResult{ctrl: ctrl}
	mock.recorder = &MockTestResultMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTestResult) EXPECT() *MockTestResultMockRecorder {
	return m.recorder
}

// Findings mocks base method.
func (m *MockTestResult) Findings(ctx context.Context) ([]testapi.FindingData, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Findings", ctx)
	ret0, _ := ret[0].([]testapi.FindingData)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Findings indicates an expected call of Findings.
func (mr *MockTestResultMockRecorder) Findings(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Findings", reflect.TypeOf((*MockTestResult)(nil).Findings), ctx)
}

// GetEffectiveSummary mocks base method.
func (m *MockTestResult) GetEffectiveSummary() *testapi.FindingSummary {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEffectiveSummary")
	ret0, _ := ret[0].(*testapi.FindingSummary)
	return ret0
}

// GetEffectiveSummary indicates an expected call of GetEffectiveSummary.
func (mr *MockTestResultMockRecorder) GetEffectiveSummary() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEffectiveSummary", reflect.TypeOf((*MockTestResult)(nil).GetEffectiveSummary))
}

// GetErrors mocks base method.
func (m *MockTestResult) GetErrors() *[]testapi.IoSnykApiCommonError {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetErrors")
	ret0, _ := ret[0].(*[]testapi.IoSnykApiCommonError)
	return ret0
}

// GetErrors indicates an expected call of GetErrors.
func (mr *MockTestResultMockRecorder) GetErrors() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetErrors", reflect.TypeOf((*MockTestResult)(nil).GetErrors))
}

// GetOutcome mocks base method.
func (m *MockTestResult) GetOutcome() *testapi.PassFail {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOutcome")
	ret0, _ := ret[0].(*testapi.PassFail)
	return ret0
}

// GetOutcome indicates an expected call of GetOutcome.
func (mr *MockTestResultMockRecorder) GetOutcome() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOutcome", reflect.TypeOf((*MockTestResult)(nil).GetOutcome))
}

// GetOutcomeReason mocks base method.
func (m *MockTestResult) GetOutcomeReason() *testapi.TestOutcomeReason {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOutcomeReason")
	ret0, _ := ret[0].(*testapi.TestOutcomeReason)
	return ret0
}

// GetOutcomeReason indicates an expected call of GetOutcomeReason.
func (mr *MockTestResultMockRecorder) GetOutcomeReason() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOutcomeReason", reflect.TypeOf((*MockTestResult)(nil).GetOutcomeReason))
}

// GetRawSummary mocks base method.
func (m *MockTestResult) GetRawSummary() *testapi.FindingSummary {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRawSummary")
	ret0, _ := ret[0].(*testapi.FindingSummary)
	return ret0
}

// GetRawSummary indicates an expected call of GetRawSummary.
func (mr *MockTestResultMockRecorder) GetRawSummary() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRawSummary", reflect.TypeOf((*MockTestResult)(nil).GetRawSummary))
}

// GetState mocks base method.
func (m *MockTestResult) GetState() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetState")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetState indicates an expected call of GetState.
func (mr *MockTestResultMockRecorder) GetState() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetState", reflect.TypeOf((*MockTestResult)(nil).GetState))
}

// GetTestID mocks base method.
func (m *MockTestResult) GetTestID() *uuid.UUID {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTestID")
	ret0, _ := ret[0].(*uuid.UUID)
	return ret0
}

// GetTestID indicates an expected call of GetTestID.
func (mr *MockTestResultMockRecorder) GetTestID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTestID", reflect.TypeOf((*MockTestResult)(nil).GetTestID))
}

// GetWarnings mocks base method.
func (m *MockTestResult) GetWarnings() *[]testapi.IoSnykApiCommonError {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetWarnings")
	ret0, _ := ret[0].(*[]testapi.IoSnykApiCommonError)
	return ret0
}

// GetWarnings indicates an expected call of GetWarnings.
func (mr *MockTestResultMockRecorder) GetWarnings() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetWarnings", reflect.TypeOf((*MockTestResult)(nil).GetWarnings))
}

// MockTestHandle is a mock of TestHandle interface.
type MockTestHandle struct {
	ctrl     *gomock.Controller
	recorder *MockTestHandleMockRecorder
}

// MockTestHandleMockRecorder is the mock recorder for MockTestHandle.
type MockTestHandleMockRecorder struct {
	mock *MockTestHandle
}

// NewMockTestHandle creates a new mock instance.
func NewMockTestHandle(ctrl *gomock.Controller) *MockTestHandle {
	mock := &MockTestHandle{ctrl: ctrl}
	mock.recorder = &MockTestHandleMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTestHandle) EXPECT() *MockTestHandleMockRecorder {
	return m.recorder
}

// Done mocks base method.
func (m *MockTestHandle) Done() <-chan struct{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Done")
	ret0, _ := ret[0].(<-chan struct{})
	return ret0
}

// Done indicates an expected call of Done.
func (mr *MockTestHandleMockRecorder) Done() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Done", reflect.TypeOf((*MockTestHandle)(nil).Done))
}

// Result mocks base method.
func (m *MockTestHandle) Result() testapi.TestResult {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Result")
	ret0, _ := ret[0].(testapi.TestResult)
	return ret0
}

// Result indicates an expected call of Result.
func (mr *MockTestHandleMockRecorder) Result() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Result", reflect.TypeOf((*MockTestHandle)(nil).Result))
}

// Wait mocks base method.
func (m *MockTestHandle) Wait(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Wait", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// Wait indicates an expected call of Wait.
func (mr *MockTestHandleMockRecorder) Wait(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Wait", reflect.TypeOf((*MockTestHandle)(nil).Wait), ctx)
}

// MockTestClient is a mock of TestClient interface.
type MockTestClient struct {
	ctrl     *gomock.Controller
	recorder *MockTestClientMockRecorder
}

// MockTestClientMockRecorder is the mock recorder for MockTestClient.
type MockTestClientMockRecorder struct {
	mock *MockTestClient
}

// NewMockTestClient creates a new mock instance.
func NewMockTestClient(ctrl *gomock.Controller) *MockTestClient {
	mock := &MockTestClient{ctrl: ctrl}
	mock.recorder = &MockTestClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTestClient) EXPECT() *MockTestClientMockRecorder {
	return m.recorder
}

// StartTest mocks base method.
func (m *MockTestClient) StartTest(ctx context.Context, params testapi.StartTestParams) (testapi.TestHandle, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StartTest", ctx, params)
	ret0, _ := ret[0].(testapi.TestHandle)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StartTest indicates an expected call of StartTest.
func (mr *MockTestClientMockRecorder) StartTest(ctx, params interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartTest", reflect.TypeOf((*MockTestClient)(nil).StartTest), ctx, params)
}
