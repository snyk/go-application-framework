package localworkflows

import (
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestInitToolsWorkflowShow(t *testing.T) {
	// Create a test engine
	engine := workflow.NewDefaultWorkFlowEngine()
	config := configuration.New()
	config.Set(configuration.FLAG_EXPERIMENTAL, true)
	engine.SetConfiguration(config)

	// Initialize the workflow show
	err := InitToolsWorkflowShow(engine)
	assert.NoError(t, err)

	// Verify the workflow is registered
	workflow, exists := engine.GetWorkflow(WORKFLOWID_TOOLS_WORKFLOW_SHOW)
	assert.True(t, exists)
	assert.NotNil(t, workflow)
	assert.True(t, workflow.IsVisible())
}

func TestToolsWorkflowShowEntryPoint(t *testing.T) {
	// Create a test engine with some workflows
	engine := workflow.NewDefaultWorkFlowEngine()
	config := configuration.New()
	config.Set(configuration.FLAG_EXPERIMENTAL, true)
	engine.SetConfiguration(config)

	// Register a test workflow
	testWorkflowID := workflow.NewWorkflowIdentifier("test")
	testFlags := pflag.NewFlagSet("test", pflag.ExitOnError)
	testFlags.String("test-flag", "default", "test flag description")
	testFlags.Bool("test-bool", false, "test boolean flag")
	
	_, err := engine.Register(testWorkflowID, workflow.ConfigurationOptionsFromFlagset(testFlags), func(ctx workflow.InvocationContext, data []workflow.Data) ([]workflow.Data, error) {
		return nil, nil
	})
	assert.NoError(t, err)

	// Initialize the workflow show
	err = InitToolsWorkflowShow(engine)
	assert.NoError(t, err)

	// Create invocation context
	logger := zerolog.New(zerolog.NewConsoleWriter())
	invocationCtx := &mockInvocationContext{
		config:  config,
		engine:  engine,
		logger:  &logger,
	}

	// Test missing workflow name
	config.Set(workflowNameFlag, "")
	result, err := toolsWorkflowShowEntryPoint(invocationCtx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow name is required")
	assert.Nil(t, result)

	// Test non-existent workflow
	config.Set(workflowNameFlag, "nonexistent")
	result, err = toolsWorkflowShowEntryPoint(invocationCtx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow 'nonexistent' not found")
	assert.Nil(t, result)

	// Test successful workflow show
	config.Set(workflowNameFlag, "test")
	result, err = toolsWorkflowShowEntryPoint(invocationCtx, nil)
	assert.NoError(t, err)
	assert.Len(t, result, 1)

	// Verify the output contains workflow information
	data := result[0]
	payload := data.GetPayload()
	assert.NotNil(t, payload)
	assert.Equal(t, "text/plain", data.GetContentType())

	// Test JSON output
	config.Set(toolsShowJsonFlag, true)
	result, err = toolsWorkflowShowEntryPoint(invocationCtx, nil)
	assert.NoError(t, err)
	assert.Len(t, result, 1)

	// Verify JSON output can be parsed
	data = result[0]
	payload = data.GetPayload()
	assert.Equal(t, "application/json", data.GetContentType())

	// Try to parse as JSON
	var workflowDetail WorkflowDetail
	payloadBytes, ok := payload.([]byte)
	assert.True(t, ok)
	err = json.Unmarshal(payloadBytes, &workflowDetail)
	assert.NoError(t, err)
	assert.Equal(t, "test", workflowDetail.Command)
	assert.True(t, workflowDetail.Visible)
	assert.Equal(t, "active", workflowDetail.Status)
	assert.Len(t, workflowDetail.Flags, 2) // test-flag and test-bool
}

func TestWorkflowDetail(t *testing.T) {
	detail := WorkflowDetail{
		Command:      "test.command",
		Identifier:   "flw://test.command",
		Visible:      true,
		Experimental: false,
		Description:  "Test workflow description",
		Status:       "active",
		Flags: []FlagDetail{
			{
				Name:         "test-flag",
				Type:         "string",
				DefaultValue: "default",
				Description:  "Test flag description",
				Required:     false,
				Shorthand:    "t",
			},
		},
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(detail)
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Test JSON unmarshaling
	var unmarshaled WorkflowDetail
	err = json.Unmarshal(jsonData, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, detail.Command, unmarshaled.Command)
	assert.Equal(t, detail.Identifier, unmarshaled.Identifier)
	assert.Equal(t, detail.Visible, unmarshaled.Visible)
	assert.Equal(t, detail.Experimental, unmarshaled.Experimental)
	assert.Equal(t, detail.Description, unmarshaled.Description)
	assert.Equal(t, detail.Status, unmarshaled.Status)
	assert.Len(t, unmarshaled.Flags, 1)
	assert.Equal(t, detail.Flags[0].Name, unmarshaled.Flags[0].Name)
}

func TestFlagDetail(t *testing.T) {
	flag := FlagDetail{
		Name:         "test-flag",
		Type:         "string",
		DefaultValue: "default",
		Description:  "Test flag description",
		Required:     true,
		Shorthand:    "t",
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(flag)
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Test JSON unmarshaling
	var unmarshaled FlagDetail
	err = json.Unmarshal(jsonData, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, flag.Name, unmarshaled.Name)
	assert.Equal(t, flag.Type, unmarshaled.Type)
	assert.Equal(t, flag.DefaultValue, unmarshaled.DefaultValue)
	assert.Equal(t, flag.Description, unmarshaled.Description)
	assert.Equal(t, flag.Required, unmarshaled.Required)
	assert.Equal(t, flag.Shorthand, unmarshaled.Shorthand)
}



func TestGetWorkflowDescription(t *testing.T) {
	// Test known workflows
	assert.Equal(t, "Authenticate with Snyk using OAuth or API token", getWorkflowDescription("auth"))
	assert.Equal(t, "Display information about the currently authenticated user", getWorkflowDescription("whoami"))
	assert.Equal(t, "List all available workflows", getWorkflowDescription("tools workflow-list"))
	assert.Equal(t, "Show detailed information about a specific workflow", getWorkflowDescription("tools workflow-show"))

	// Test unknown workflow
	assert.Equal(t, "No description available", getWorkflowDescription("unknown-workflow"))
}

func TestCreateWorkflowDetailTextOutput(t *testing.T) {
	detail := WorkflowDetail{
		Command:      "test.command",
		Identifier:   "flw://test.command",
		Visible:      true,
		Experimental: false,
		Description:  "Test workflow description",
		Status:       "active",
		Flags: []FlagDetail{
			{
				Name:         "test-flag",
				Type:         "string",
				DefaultValue: "default",
				Description:  "Test flag description",
				Required:     false,
				Shorthand:    "t",
			},
		},
	}

	output := createWorkflowDetailTextOutput(detail)
	assert.Contains(t, output, "Workflow: test.command")
	assert.Contains(t, output, "Identifier: flw://test.command")
	assert.Contains(t, output, "Status: active")
	assert.Contains(t, output, "Description:")
	assert.Contains(t, output, "Test workflow description")
	assert.Contains(t, output, "Flags:")
	assert.Contains(t, output, "-t, --test-flag")
	assert.Contains(t, output, "Type: string")
	assert.Contains(t, output, "Default: default")
	assert.Contains(t, output, "Description: Test flag description")
}

 