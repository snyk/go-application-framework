package localworkflows

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestInitToolsWorkflowList(t *testing.T) {
	// Create a test engine
	engine := workflow.NewDefaultWorkFlowEngine()
	config := configuration.New()
	config.Set(configuration.FLAG_EXPERIMENTAL, true)
	engine.SetConfiguration(config)

	// Initialize the workflow list
	err := InitToolsWorkflowList(engine)
	assert.NoError(t, err)

	// Verify the workflow is registered
	workflow, exists := engine.GetWorkflow(WORKFLOWID_TOOLS_WORKFLOW_LIST)
	assert.True(t, exists)
	assert.NotNil(t, workflow)
	assert.True(t, workflow.IsVisible())
}

func TestToolsWorkflowListEntryPoint(t *testing.T) {
	// Create a test engine with some workflows
	engine := workflow.NewDefaultWorkFlowEngine()
	config := configuration.New()
	config.Set(configuration.FLAG_EXPERIMENTAL, true)
	engine.SetConfiguration(config)

	// Register a test workflow
	testWorkflowID := workflow.NewWorkflowIdentifier("test")
	testFlags := pflag.NewFlagSet("test", pflag.ExitOnError)
	testFlags.String("test-flag", "", "test flag")

	_, err := engine.Register(testWorkflowID, workflow.ConfigurationOptionsFromFlagset(testFlags), func(ctx workflow.InvocationContext, data []workflow.Data) ([]workflow.Data, error) {
		return nil, nil
	})
	assert.NoError(t, err)

	// Initialize the workflow list
	err = InitToolsWorkflowList(engine)
	assert.NoError(t, err)

	// Create invocation context
	logger := zerolog.New(zerolog.NewConsoleWriter())
	invocationCtx := &mockInvocationContext{
		config: config,
		engine: engine,
		logger: &logger,
	}

	// Test basic functionality
	result, err := toolsWorkflowListEntryPoint(invocationCtx, nil)
	assert.NoError(t, err)
	assert.Len(t, result, 1)

	// Verify the output contains workflow information
	data := result[0]
	payload := data.GetPayload()
	assert.NotNil(t, payload)

	// Test JSON output
	config.Set(toolsJsonFlag, true)
	result, err = toolsWorkflowListEntryPoint(invocationCtx, nil)
	assert.NoError(t, err)
	assert.Len(t, result, 1)

	// Verify JSON output can be parsed
	data = result[0]
	payload = data.GetPayload()
	assert.Equal(t, "application/json", data.GetContentType())

	// Try to parse as JSON
	var hierarchicalInfo HierarchicalWorkflowInfo
	payloadBytes, ok := payload.([]byte)
	assert.True(t, ok)
	err = json.Unmarshal(payloadBytes, &hierarchicalInfo)
	assert.NoError(t, err)
	assert.NotEmpty(t, hierarchicalInfo.Groups)

	// Verify at least our test workflow is in the list
	found := false
	for _, group := range hierarchicalInfo.Groups {
		for _, info := range group.Workflows {
			if info.Command == "test" {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	assert.True(t, found, "Test workflow should be in the list")
}

func TestWorkflowInfo(t *testing.T) {
	info := WorkflowInfo{
		Command:      "test.command",
		Identifier:   "flw://test.command",
		Visible:      true,
		Experimental: false,
		Flags:        []string{"flag1", "flag2"},
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(info)
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Test JSON unmarshaling
	var unmarshaled WorkflowInfo
	err = json.Unmarshal(jsonData, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, info.Command, unmarshaled.Command)
	assert.Equal(t, info.Identifier, unmarshaled.Identifier)
	assert.Equal(t, info.Visible, unmarshaled.Visible)
	assert.Equal(t, info.Experimental, unmarshaled.Experimental)
	assert.Equal(t, info.Flags, unmarshaled.Flags)
}

// Mock invocation context for testing
type mockInvocationContext struct {
	config configuration.Configuration
	engine workflow.Engine
	logger *zerolog.Logger
}

func (m *mockInvocationContext) GetConfiguration() configuration.Configuration {
	return m.config
}

func (m *mockInvocationContext) GetEngine() workflow.Engine {
	return m.engine
}

func (m *mockInvocationContext) GetEnhancedLogger() *zerolog.Logger {
	return m.logger
}

func (m *mockInvocationContext) GetWorkflowIdentifier() workflow.Identifier {
	return nil
}

func (m *mockInvocationContext) GetAnalytics() analytics.Analytics {
	return nil
}

func (m *mockInvocationContext) GetNetworkAccess() networking.NetworkAccess {
	return nil
}

func (m *mockInvocationContext) GetLogger() *log.Logger {
	return nil
}

func (m *mockInvocationContext) GetUserInterface() ui.UserInterface {
	return nil
}

func (m *mockInvocationContext) GetRuntimeInfo() runtimeinfo.RuntimeInfo {
	return nil
}
