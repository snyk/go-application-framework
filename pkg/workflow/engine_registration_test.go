package workflow_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func noopRegistrationCallback(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
	return nil, nil
}

func Test_EngineRegister_FailedFlagRegistrationLeavesNoWorkflow(t *testing.T) {
	ctrl := gomock.NewController(t)
	config := mocks.NewMockConfiguration(ctrl)
	config.EXPECT().AddFlagSet(gomock.Any()).Return(errors.New("bind failed"))
	engine := workflow.NewWorkFlowEngine(config)

	id := workflow.NewWorkflowIdentifier("failing flags")
	flags := pflag.NewFlagSet("failing", pflag.ContinueOnError)
	flags.String("some-flag", "", "")

	entry, err := engine.Register(id, workflow.ConfigurationOptionsFromFlagset(flags), noopRegistrationCallback)

	require.ErrorContains(t, err, "bind failed")
	assert.Nil(t, entry)
	_, found := engine.GetWorkflow(id)
	assert.False(t, found, "a failed registration must not leave the workflow registered")
	assert.Empty(t, engine.GetWorkflows())
}

// Run with -race: registering while other goroutines list and look up workflows must not race on the workflow map.
func Test_EngineRegister_ConcurrentWithQueriesDoesNotRace(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	const count = 50
	idFor := func(i int) workflow.Identifier {
		return workflow.NewWorkflowIdentifier(fmt.Sprintf("concurrent %d", i))
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range count {
			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			_, err := engine.Register(idFor(i), workflow.ConfigurationOptionsFromFlagset(flags), noopRegistrationCallback)
			assert.NoError(t, err)
		}
	})
	for range 2 {
		wg.Go(func() {
			for i := range count {
				_ = engine.GetWorkflows()
				_, _ = engine.GetWorkflow(idFor(i))
			}
		})
	}
	wg.Wait()

	assert.Len(t, engine.GetWorkflows(), count)
}
