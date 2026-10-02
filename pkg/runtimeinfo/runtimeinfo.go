package runtimeinfo

import "errors"

//go:generate go tool github.com/golang/mock/mockgen -source=runtimeinfo.go -destination ../mocks/runtimeinfo.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/runtimeinfo/

// ErrNoMachineID is returned by GetMachineID when no stable machine identifier is available.
var ErrNoMachineID = errors.New("no stable machine identifier available")

// RuntimeInfo describes the runtime the application runs in, grouped into application and machine information.
type RuntimeInfo interface {
	// application
	GetName() string
	SetName(string)

	GetVersion() string
	SetVersion(string)

	// machine

	// GetMachineID returns the identifier of the machine the application runs on, or ErrNoMachineID when no stable identifier is available.
	GetMachineID() (string, error)
}

type opt func(RuntimeInfo)

type defaultRuntimeInfo struct {
	name    string
	version string
}

var _ RuntimeInfo = (*defaultRuntimeInfo)(nil)

func (ri *defaultRuntimeInfo) GetName() string {
	return ri.name
}

func (ri *defaultRuntimeInfo) SetName(n string) {
	ri.name = n
}

func (ri *defaultRuntimeInfo) GetVersion() string {
	return ri.version
}

func (ri *defaultRuntimeInfo) SetVersion(v string) {
	ri.version = v
}

func (ri *defaultRuntimeInfo) GetMachineID() (string, error) {
	return "", ErrNoMachineID
}

func New(opts ...opt) RuntimeInfo {
	ri := &defaultRuntimeInfo{}

	for _, fn := range opts {
		fn(ri)
	}

	return ri
}

func WithName(n string) opt {
	return func(ri RuntimeInfo) {
		ri.SetName(n)
	}
}

func WithVersion(v string) opt {
	return func(ri RuntimeInfo) {
		ri.SetVersion(v)
	}
}
