// Code generated by MockGen. DO NOT EDIT.
// Source: runtimeinfo.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockRuntimeInfo is a mock of RuntimeInfo interface.
type MockRuntimeInfo struct {
	ctrl     *gomock.Controller
	recorder *MockRuntimeInfoMockRecorder
}

// MockRuntimeInfoMockRecorder is the mock recorder for MockRuntimeInfo.
type MockRuntimeInfoMockRecorder struct {
	mock *MockRuntimeInfo
}

// NewMockRuntimeInfo creates a new mock instance.
func NewMockRuntimeInfo(ctrl *gomock.Controller) *MockRuntimeInfo {
	mock := &MockRuntimeInfo{ctrl: ctrl}
	mock.recorder = &MockRuntimeInfoMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRuntimeInfo) EXPECT() *MockRuntimeInfoMockRecorder {
	return m.recorder
}

// GetName mocks base method.
func (m *MockRuntimeInfo) GetName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetName")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetName indicates an expected call of GetName.
func (mr *MockRuntimeInfoMockRecorder) GetName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetName", reflect.TypeOf((*MockRuntimeInfo)(nil).GetName))
}

// GetVersion mocks base method.
func (m *MockRuntimeInfo) GetVersion() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetVersion")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetVersion indicates an expected call of GetVersion.
func (mr *MockRuntimeInfoMockRecorder) GetVersion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetVersion", reflect.TypeOf((*MockRuntimeInfo)(nil).GetVersion))
}

// SetName mocks base method.
func (m *MockRuntimeInfo) SetName(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetName", arg0)
}

// SetName indicates an expected call of SetName.
func (mr *MockRuntimeInfoMockRecorder) SetName(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetName", reflect.TypeOf((*MockRuntimeInfo)(nil).SetName), arg0)
}

// SetVersion mocks base method.
func (m *MockRuntimeInfo) SetVersion(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetVersion", arg0)
}

// SetVersion indicates an expected call of SetVersion.
func (mr *MockRuntimeInfoMockRecorder) SetVersion(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetVersion", reflect.TypeOf((*MockRuntimeInfo)(nil).SetVersion), arg0)
}
