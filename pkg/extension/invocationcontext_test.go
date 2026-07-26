package extension

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestPluginInvocationContext_GetRuntimeInfo_NeverNil(t *testing.T) {
	id := workflow.NewWorkflowIdentifier("hello")
	c := newPluginInvocationContext(context.Background(), id, configuration.New(), "", "", nil, nil)

	ri := c.GetRuntimeInfo()
	require.NotNil(t, ri, "GetRuntimeInfo must never return nil, or host code written for in-process use panics when run as an extension")
	assert.Equal(t, "", ri.GetName())
	assert.Equal(t, "", ri.GetVersion())
}

func TestPluginInvocationContext_GetRuntimeInfo_MirrorsHostValues(t *testing.T) {
	id := workflow.NewWorkflowIdentifier("hello")
	ri := runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.2.3"))
	c := newPluginInvocationContext(context.Background(), id, configuration.New(), "", "", nil, ri)

	assert.Equal(t, "snyk-cli", c.GetRuntimeInfo().GetName())
	assert.Equal(t, "1.2.3", c.GetRuntimeInfo().GetVersion())
}
