package wiring_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributors"
	"github.com/snyk/go-application-framework/internal/contributors/wiring"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestInit_respectsCaptureFlag(t *testing.T) {
	contributors.ResetCaptureForTest()

	disabled := workflow.NewDefaultWorkFlowEngine()
	disabled.GetConfiguration().Set(contributors.ConfigurationKeyCaptureEnabled, false)
	require.NoError(t, wiring.Init(disabled))
	assert.Nil(t, contributors.GetSink())

	contributors.ResetCaptureForTest()

	enabled := workflow.NewDefaultWorkFlowEngine()
	enabled.GetConfiguration().Set(contributors.ConfigurationKeyCaptureEnabled, true)
	require.NoError(t, wiring.Init(enabled))
	assert.NotNil(t, contributors.GetSink())
}

func TestRepoPathFromConfig(t *testing.T) {
	t.Parallel()

	config := configuration.NewWithOpts()
	assert.Equal(t, ".", wiring.RepoPathFromConfig(nil))
	assert.Equal(t, ".", wiring.RepoPathFromConfig(config))

	config.Set(configuration.INPUT_DIRECTORY, []string{"/tmp/repo"})
	assert.Equal(t, "/tmp/repo", wiring.RepoPathFromConfig(config))
}

func TestShouldSkipEmit(t *testing.T) {
	t.Parallel()

	assert.False(t, wiring.ShouldSkipEmit(nil))
	assert.False(t, wiring.ShouldSkipEmit(fakeInvokeOutput{workflow.NewWorkflowIdentifier("monitor")}))
	assert.True(t, wiring.ShouldSkipEmit(fakeInvokeOutput{localworkflows.WORKFLOWID_FILTER_FINDINGS}))
	assert.True(t, wiring.ShouldSkipEmit(fakeInvokeOutput{localworkflows.WORKFLOWID_OUTPUT_WORKFLOW}))
	assert.True(t, wiring.ShouldSkipEmit(fakeInvokeOutput{localworkflows.WORKFLOWID_REPORT_ANALYTICS}))
}

func TestWaitForEmit_blocksUntilCompletion(t *testing.T) {
	t.Parallel()

	var completed atomic.Bool
	logger := zerolog.Nop()

	done := make(chan struct{})
	go func() {
		wiring.WaitForEmit(context.Background(), &logger, func() error {
			time.Sleep(20 * time.Millisecond)
			completed.Store(true)
			return nil
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waitForEmit did not return")
	}
	assert.True(t, completed.Load())
}

func TestWaitForEmit_waitsForEmitAfterContextCancel(t *testing.T) {
	t.Parallel()

	var completed atomic.Bool
	logger := zerolog.Nop()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	wiring.WaitForEmit(ctx, &logger, func() error {
		completed.Store(true)
		return errors.New("emit failed")
	})

	assert.True(t, completed.Load())
}

type fakeInvokeOutput struct {
	id workflow.Identifier
}

func (f fakeInvokeOutput) GetWorkflowIdentifier() workflow.Identifier { return f.id }
func (fakeInvokeOutput) GetOutput() []workflow.Data                   { return nil }
func (fakeInvokeOutput) GetError() error                              { return nil }
