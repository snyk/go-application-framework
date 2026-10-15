package machineid

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// errorChain renders err and every error beneath it, so a failure shows the operating system error
// behind a wrapper's title.
func errorChain(err error) string {
	if err == nil {
		return ""
	}
	var parts []string
	var walk func(error)
	walk = func(e error) {
		parts = append(parts, fmt.Sprintf("%v", e))
		if many, ok := e.(interface{ Unwrap() []error }); ok {
			for _, next := range many.Unwrap() {
				walk(next)
			}
			return
		}
		if next := errors.Unwrap(e); next != nil {
			walk(next)
		}
	}
	walk(err)
	return strings.Join(parts, "\n  caused by: ")
}

func TestIntegration_InMemoryConfigurationResolvesThroughTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	config := configuration.NewInMemory()
	config.AddDefaultValue(configuration.MACHINE_ID, m.resolve())

	id := machineID(t, config)

	require.True(t, valid(id))
	require.Equal(t, id, readFile(t, m.shared.perUser).MachineID)
}

func TestErrorChainListsEveryCause(t *testing.T) {
	cause := &fs.PathError{Op: "open", Path: "machine-id.json", Err: syscall.ENOENT}
	err := errors.Join(cli.NewMachineIDFileUnreadableError("unreadable", snyk_errors.WithCause(cause)))

	chain := errorChain(err)

	require.Contains(t, chain, "unreadable")
	require.Contains(t, chain, "open machine-id.json")
	require.Contains(t, chain, syscall.ENOENT.Error())
}

func TestIntegration_ConcurrentRunsOnOneMachineConvergeOnOneID(t *testing.T) {
	m := newIsolatedMachine(t)

	const runs = 8
	results := make([]string, runs)
	var wg sync.WaitGroup
	wg.Add(runs)
	for i := 0; i < runs; i++ {
		go func(i int) {
			defer wg.Done()
			config := configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
			config.AddDefaultValue(configuration.MACHINE_ID, m.resolve())
			value, err := config.GetStringWithError(configuration.MACHINE_ID)
			assert.NoError(t, err, errorChain(err))
			results[i] = value
		}(i)
	}
	wg.Wait()

	require.NotEmpty(t, results[0])
	for i := 1; i < runs; i++ {
		require.Equal(t, results[0], results[i], "independent runs must converge on the same machine id")
	}
	require.Equal(t, results[0], readFile(t, m.shared.perUser).MachineID)
}
