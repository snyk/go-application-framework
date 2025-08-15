package localworkflows

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	toolsWorkflowShowName = "tools.workflow-show"
	toolsShowJsonFlag     = "json"
	workflowNameFlag      = "workflow"
)

// define a new workflow identifier for this workflow
var WORKFLOWID_TOOLS_WORKFLOW_SHOW workflow.Identifier = workflow.NewWorkflowIdentifier(toolsWorkflowShowName)

// WorkflowDetail represents detailed information about a specific workflow
type WorkflowDetail struct {
	Command       string            `json:"command"`
	Identifier    string            `json:"identifier"`
	Visible       bool              `json:"visible"`
	Experimental  bool              `json:"experimental"`
	Description   string            `json:"description,omitempty"`
	Flags         []FlagDetail      `json:"flags,omitempty"`
	Status        string            `json:"status"`
	Error         string            `json:"error,omitempty"`
}

// FlagDetail represents detailed information about a workflow flag
type FlagDetail struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	DefaultValue string `json:"default_value,omitempty"`
	Description  string `json:"description,omitempty"`
	Required     bool   `json:"required"`
	Shorthand    string `json:"shorthand,omitempty"`
}

// InitToolsWorkflowShow initializes the tools workflow show workflow before registering it with the engine.
func InitToolsWorkflowShow(engine workflow.Engine) error {
	// initialize workflow configuration
	config := pflag.NewFlagSet(toolsWorkflowShowName, pflag.ExitOnError)
	// add json flag to configuration
	config.Bool(toolsShowJsonFlag, false, "output in json format")
	// add workflow name flag to specify which workflow to show
	config.String(workflowNameFlag, "", "name of the workflow to show details for (required)")

	// register workflow with engine
	_, err := engine.Register(WORKFLOWID_TOOLS_WORKFLOW_SHOW, workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(config)), toolsWorkflowShowEntryPoint)
	return err
}

// toolsWorkflowShowEntryPoint is the entry point for the tools workflow show workflow.
// it shows detailed information about a specific workflow
func toolsWorkflowShowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	engine := invocationCtx.GetEngine()

	// get the workflow name from configuration
	workflowName, err := config.GetStringWithError(workflowNameFlag)
	if err != nil || workflowName == "" {
		return nil, fmt.Errorf("workflow name is required. Use --workflow <workflow-name> to specify a workflow")
	}

	// find the workflow by name
	var targetWorkflow workflow.Identifier
	var targetEntry workflow.Entry
	found := false

	workflows := engine.GetWorkflows()
	for _, workflowID := range workflows {
		command := workflow.GetCommandFromWorkflowIdentifier(workflowID)
		if command == workflowName {
			targetWorkflow = workflowID
			targetEntry, found = engine.GetWorkflow(workflowID)
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("workflow '%s' not found. Use 'tools workflow-list' to see available workflows", workflowName)
	}

	// create detailed workflow information
	workflowDetail := createWorkflowDetail(targetWorkflow, targetEntry, engine, config)

	// return json output if json flag is set
	if config.GetBool(toolsShowJsonFlag) {
		workflowDetailJSON, err := json.MarshalIndent(workflowDetail, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("error marshaling workflow details: %w", err)
		}

		workflowData := createWorkflowShowData(workflowDetailJSON, "application/json", logger, config)
		return []workflow.Data{workflowData}, nil
	}

	// return formatted text output
	outputText := createWorkflowDetailTextOutput(workflowDetail)
	workflowData := createWorkflowShowData(outputText, "text/plain", logger, config)
	return []workflow.Data{workflowData}, nil
}

// createWorkflowDetail creates detailed information about a workflow
func createWorkflowDetail(workflowID workflow.Identifier, entry workflow.Entry, engine workflow.Engine, config configuration.Configuration) WorkflowDetail {
	command := workflow.GetCommandFromWorkflowIdentifier(workflowID)
	
	// Check if this specific workflow is experimental
	isExperimental := false
	if configOpts := entry.GetConfigurationOptions(); configOpts != nil {
		if flagset := workflow.FlagsetFromConfigurationOptions(configOpts); flagset != nil {
			isExperimental = config_utils.IsExperimental(flagset)
		}
	}

	// Determine status
	status := "active"
	if !entry.IsVisible() {
		status = "hidden"
	}

	// Get flags information
	var flags []FlagDetail
	if configOpts := entry.GetConfigurationOptions(); configOpts != nil {
		if flagset := workflow.FlagsetFromConfigurationOptions(configOpts); flagset != nil {
			flagset.VisitAll(func(flag *pflag.Flag) {
				flagDetail := FlagDetail{
					Name:         flag.Name,
					Type:         getFlagType(flag),
					DefaultValue: flag.DefValue,
					Description:  flag.Usage,
					Required:     false, // pflag doesn't have a Required field, we'll set it to false for now
					Shorthand:    flag.Shorthand,
				}
				flags = append(flags, flagDetail)
			})
			sort.Slice(flags, func(i, j int) bool {
				return flags[i].Name < flags[j].Name
			})
		}
	}

	return WorkflowDetail{
		Command:      command,
		Identifier:   workflowID.String(),
		Visible:      entry.IsVisible(),
		Experimental: isExperimental,
		Description:  getWorkflowDescription(command),
		Flags:        flags,
		Status:       status,
	}
}

// getFlagType determines the type of a flag
func getFlagType(flag *pflag.Flag) string {
	switch flag.Value.Type() {
	case "bool":
		return "boolean"
	case "string":
		return "string"
	case "int":
		return "integer"
	case "int64":
		return "integer"
	case "uint":
		return "unsigned integer"
	case "uint64":
		return "unsigned integer"
	case "float64":
		return "float"
	case "duration":
		return "duration"
	default:
		return "unknown"
	}
}

// getWorkflowDescription returns a description for a workflow based on its command
func getWorkflowDescription(command string) string {
	descriptions := map[string]string{
		"auth":              "Authenticate with Snyk using OAuth or API token",
		"whoami":            "Display information about the currently authenticated user",
		"config environment": "Configure the Snyk environment settings",
		"code test":         "Test your code for security vulnerabilities",
		"findings filter":   "Filter and process security findings",
		"ignore create":     "Create ignore rules for security findings",
		"datatransformation": "Transform data between different formats",
		"output":            "Output workflow results in various formats",
		"tools workflow-list": "List all available workflows",
		"tools workflow-show": "Show detailed information about a specific workflow",
		"tools connectivity-check": "Check connectivity to Snyk services",
		"analytics report":  "Report analytics data to Snyk",
	}

	if desc, exists := descriptions[command]; exists {
		return desc
	}
	return "No description available"
}

// createWorkflowDetailTextOutput creates a formatted text output for workflow details
func createWorkflowDetailTextOutput(detail WorkflowDetail) string {
	var outputLines []string
	
	// Header
	outputLines = append(outputLines, fmt.Sprintf("Workflow: %s", detail.Command))
	outputLines = append(outputLines, fmt.Sprintf("Identifier: %s", detail.Identifier))
	outputLines = append(outputLines, fmt.Sprintf("Status: %s", detail.Status))
	
	if detail.Experimental {
		outputLines = append(outputLines, "Experimental: Yes")
	}
	
	if detail.Description != "" {
		outputLines = append(outputLines, "")
		outputLines = append(outputLines, "Description:")
		outputLines = append(outputLines, fmt.Sprintf("  %s", detail.Description))
	}
	
	// Flags section
	if len(detail.Flags) > 0 {
		outputLines = append(outputLines, "")
		outputLines = append(outputLines, "Flags:")
		for _, flag := range detail.Flags {
			flagLine := fmt.Sprintf("  --%s", flag.Name)
			if flag.Shorthand != "" {
				flagLine = fmt.Sprintf("  -%s, --%s", flag.Shorthand, flag.Name)
			}
			outputLines = append(outputLines, flagLine)
			
			if flag.Type != "" {
				outputLines = append(outputLines, fmt.Sprintf("    Type: %s", flag.Type))
			}
			
			if flag.DefaultValue != "" {
				outputLines = append(outputLines, fmt.Sprintf("    Default: %s", flag.DefaultValue))
			}
			
			if flag.Description != "" {
				outputLines = append(outputLines, fmt.Sprintf("    Description: %s", flag.Description))
			}
			
			if flag.Required {
				outputLines = append(outputLines, "    Required: Yes")
			}
			
			outputLines = append(outputLines, "")
		}
	} else {
		outputLines = append(outputLines, "")
		outputLines = append(outputLines, "Flags: None")
	}
	
	return strings.Join(outputLines, "\n")
}

// createWorkflowShowData creates a new workflow.Data object for workflow show
func createWorkflowShowData(data interface{}, contentType string, logger *zerolog.Logger, config configuration.Configuration) workflow.Data {
	return workflow.NewData(
		// use new type identifier when creating new data
		workflow.NewTypeIdentifier(WORKFLOWID_TOOLS_WORKFLOW_SHOW, toolsWorkflowShowName),
		contentType,
		data,
		workflow.WithLogger(logger),
		workflow.WithConfiguration(config),
	)
} 