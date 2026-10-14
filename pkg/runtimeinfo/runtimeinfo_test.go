package runtimeinfo

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuntimeInfo_New(t *testing.T) {
	ri := New()

	assert.NotNil(t, ri)
}

func TestRuntimeInfo_NewWithName(t *testing.T) {
	ri := New(WithName("asdf"))

	assert.Equal(t, "asdf", ri.GetName())
}

func TestRuntimeInfo_NewHasNoMachineId(t *testing.T) {
	ri := New()

	machineID, err := ri.GetMachineID()

	assert.ErrorIs(t, err, ErrNoMachineID)
	assert.Empty(t, machineID)
}

func TestRuntimeInfo_NewWithVersion(t *testing.T) {
	ri := New(WithVersion("1.2.3"))

	assert.Equal(t, "1.2.3", ri.GetVersion())
}

// Run with -race: a writer can set the name and version while the machine id resolver reads them.
func TestRuntimeInfo_ConcurrentSetAndGetDoNotRace(t *testing.T) {
	ri := New()
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			ri.SetName("snyk-ls")
			ri.SetVersion("9.9.9")
		}
	})
	wg.Go(func() {
		for range 100 {
			_ = ri.GetName()
			_ = ri.GetVersion()
		}
	})
	wg.Wait()
}
