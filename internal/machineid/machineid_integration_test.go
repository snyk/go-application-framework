package machineid

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestIntegration_InMemoryConfigurationResolvesThroughTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	config := configuration.NewInMemory()
	config.AddDefaultValue(configuration.MACHINE_ID, m.resolve())

	id := machineID(t, config)

	require.True(t, valid(id))
	require.Equal(t, id, readFile(t, m.shared.perUser).MachineID)
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
			assert.NoError(t, err)
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
