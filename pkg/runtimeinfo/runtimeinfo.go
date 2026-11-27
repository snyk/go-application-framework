package runtimeinfo

import (
	"errors"
	"sync"
)

//go:generate go tool github.com/golang/mock/mockgen -source=runtimeinfo.go -destination ../mocks/runtimeinfo.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/runtimeinfo/

// ErrNoMachineID is returned by GetMachineID when no stable machine identifier is available. It may be
// joined with error catalog errors describing why, so check for it with errors.Is.
var ErrNoMachineID = errors.New("no stable machine identifier available")

// Machine describes the machine the application runs on. ID is the stable identifier; the other fields
// are descriptive and empty when they could not be determined.
type Machine struct {
	ID           string
	Hostname     string
	SerialNumber string
	StudioID     string
}

// RuntimeInfo describes the runtime the application runs in, grouped into application and machine information.
type RuntimeInfo interface {
	// application
	GetName() string
	SetName(string)

	GetVersion() string
	SetVersion(string)

	// machine

	// GetMachineID returns the machine the application runs on, or ErrNoMachineID when no stable identifier is available.
	// A non-empty Machine.ID may come with a non-nil error, such as a machine id file that could not be read; the identifier is still usable.
	GetMachineID() (Machine, error)
}

type opt func(RuntimeInfo)

type defaultRuntimeInfo struct {
	mu      sync.RWMutex
	name    string
	version string
}

var _ RuntimeInfo = (*defaultRuntimeInfo)(nil)

func (ri *defaultRuntimeInfo) GetName() string {
	ri.mu.RLock()
	defer ri.mu.RUnlock()
	return ri.name
}

func (ri *defaultRuntimeInfo) SetName(n string) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	ri.name = n
}

func (ri *defaultRuntimeInfo) GetVersion() string {
	ri.mu.RLock()
	defer ri.mu.RUnlock()
	return ri.version
}

func (ri *defaultRuntimeInfo) SetVersion(v string) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	ri.version = v
}

func (ri *defaultRuntimeInfo) GetMachineID() (Machine, error) {
	return Machine{}, ErrNoMachineID
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
