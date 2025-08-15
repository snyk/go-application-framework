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
	toolsWorkflowListName = "tools.workflow-list"
	toolsJsonFlag         = "json"
	detailedFlag          = "detailed"
)

// define a new workflow identifier for this workflow
var WORKFLOWID_TOOLS_WORKFLOW_LIST workflow.Identifier = workflow.NewWorkflowIdentifier(toolsWorkflowListName)

// WorkflowInfo represents information about a registered workflow
type WorkflowInfo struct {
	Command      string   `json:"command"`
	Identifier   string   `json:"identifier"`
	Visible      bool     `json:"visible"`
	Experimental bool     `json:"experimental"`
	Flags        []string `json:"flags,omitempty"`
	Description  string   `json:"description,omitempty"`
}

// WorkflowGroup represents a group of workflows with common properties
type WorkflowGroup struct {
	Name      string         `json:"name"`
	Workflows []WorkflowInfo `json:"workflows"`
}

// HierarchicalWorkflowInfo represents a grouped view of workflows
type HierarchicalWorkflowInfo struct {
	Groups []WorkflowGroup `json:"groups"`
}

// InitToolsWorkflowList initializes the tools workflow list workflow before registering it with the engine.
func InitToolsWorkflowList(engine workflow.Engine) error {
	// initialize workflow configuration
	config := pflag.NewFlagSet(toolsWorkflowListName, pflag.ExitOnError)
	// add json flag to configuration
	config.Bool(toolsJsonFlag, false, "output in json format")
	// add detailed flag to show more information
	config.Bool(detailedFlag, false, "show detailed information including flags")

	// register workflow with engine
	_, err := engine.Register(WORKFLOWID_TOOLS_WORKFLOW_LIST, workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(config)), toolsWorkflowListEntryPoint)
	return err
}

// toolsWorkflowListEntryPoint is the entry point for the tools workflow list workflow.
// it lists all registered workflows and their details
func toolsWorkflowListEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	engine := invocationCtx.GetEngine()

	// get all registered workflows
	workflows := engine.GetWorkflows()

	// sort workflows by command name for consistent output
	sort.Slice(workflows, func(i, j int) bool {
		cmdI := workflow.GetCommandFromWorkflowIdentifier(workflows[i])
		cmdJ := workflow.GetCommandFromWorkflowIdentifier(workflows[j])
		return cmdI < cmdJ
	})

	var workflowInfos []WorkflowInfo
	detailed := config.GetBool(detailedFlag)

	for _, workflowID := range workflows {
		command := workflow.GetCommandFromWorkflowIdentifier(workflowID)
		entry, exists := engine.GetWorkflow(workflowID)

		// Check if this specific workflow is experimental
		isExperimental := false
		if exists {
			if configOpts := entry.GetConfigurationOptions(); configOpts != nil {
				if flagset := workflow.FlagsetFromConfigurationOptions(configOpts); flagset != nil {
					isExperimental = config_utils.IsExperimental(flagset)
				}
			}
		}

		workflowInfo := WorkflowInfo{
			Command:      command,
			Identifier:   workflowID.String(),
			Visible:      exists && entry.IsVisible(),
			Experimental: isExperimental,
		}

		if detailed && exists {
			// Try to get flags information if available
			if configOpts := entry.GetConfigurationOptions(); configOpts != nil {
				if flagset := workflow.FlagsetFromConfigurationOptions(configOpts); flagset != nil {
					var flags []string
					flagset.VisitAll(func(flag *pflag.Flag) {
						flags = append(flags, flag.Name)
					})
					sort.Strings(flags)
					workflowInfo.Flags = flags
				}
			}
		}

		workflowInfos = append(workflowInfos, workflowInfo)
	}

	// return json output if json flag is set
	if config.GetBool(toolsJsonFlag) {
		// Create hierarchical structure for JSON output
		hierarchicalInfo := createHierarchicalStructure(workflowInfos)
		workflowInfosJSON, err := json.MarshalIndent(hierarchicalInfo, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("error marshaling workflow list: %w", err)
		}

		workflowData := createWorkflowListData(workflowInfosJSON, "application/json", logger, config)
		return []workflow.Data{workflowData}, nil
	}

	// return formatted text output with hierarchical structure
	outputText := createHierarchicalTextOutput(workflowInfos, detailed)
	workflowData := createWorkflowListData(outputText, "text/plain", logger, config)
	return []workflow.Data{workflowData}, nil
}

// createHierarchicalStructure creates a grouped view of workflows by properties
func createHierarchicalStructure(workflows []WorkflowInfo) HierarchicalWorkflowInfo {
	// Group workflows by properties
	activeWorkflows := []WorkflowInfo{}
	experimentalWorkflows := []WorkflowInfo{}
	hiddenWorkflows := []WorkflowInfo{}

	for _, workflow := range workflows {
		// Group by visibility and experimental status
		if !workflow.Visible {
			hiddenWorkflows = append(hiddenWorkflows, workflow)
		} else if workflow.Experimental {
			experimentalWorkflows = append(experimentalWorkflows, workflow)
		} else {
			activeWorkflows = append(activeWorkflows, workflow)
		}
	}

	// Create groups
	groups := []WorkflowGroup{}

	if len(activeWorkflows) > 0 {
		groups = append(groups, WorkflowGroup{
			Name:      "Active Workflows",
			Workflows: activeWorkflows,
		})
	}

	if len(experimentalWorkflows) > 0 {
		groups = append(groups, WorkflowGroup{
			Name:      "Experimental Workflows",
			Workflows: experimentalWorkflows,
		})
	}

	if len(hiddenWorkflows) > 0 {
		groups = append(groups, WorkflowGroup{
			Name:      "Hidden Workflows",
			Workflows: hiddenWorkflows,
		})
	}

	return HierarchicalWorkflowInfo{
		Groups: groups,
	}
}

// createHierarchicalTextOutput creates a grouped text output
func createHierarchicalTextOutput(workflows []WorkflowInfo, detailed bool) string {
	var outputLines []string
	outputLines = append(outputLines, "Registered Workflows:")
	outputLines = append(outputLines, "")
	
	// Group workflows by properties
	activeWorkflows := []WorkflowInfo{}
	experimentalWorkflows := []WorkflowInfo{}
	hiddenWorkflows := []WorkflowInfo{}
	
	for _, workflow := range workflows {
		if !workflow.Visible {
			hiddenWorkflows = append(hiddenWorkflows, workflow)
		} else if workflow.Experimental {
			experimentalWorkflows = append(experimentalWorkflows, workflow)
		} else {
			activeWorkflows = append(activeWorkflows, workflow)
		}
	}
	
	// Output grouped workflows
	if len(activeWorkflows) > 0 {
		outputLines = append(outputLines, "✅ Active Workflows:")
		outputLines = append(outputLines, formatWorkflowGroup(activeWorkflows, detailed, 2))
		outputLines = append(outputLines, "")
	}
	
	if len(experimentalWorkflows) > 0 {
		outputLines = append(outputLines, "🧪 Experimental Workflows:")
		outputLines = append(outputLines, formatWorkflowGroup(experimentalWorkflows, detailed, 2))
		outputLines = append(outputLines, "")
	}
	
	if len(hiddenWorkflows) > 0 {
		outputLines = append(outputLines, "👻 Hidden Workflows:")
		outputLines = append(outputLines, formatWorkflowGroup(hiddenWorkflows, detailed, 2))
		outputLines = append(outputLines, "")
	}
	
	return strings.Join(outputLines, "\n")
}



// formatWorkflowGroup formats a group of workflows for text output
func formatWorkflowGroup(workflows []WorkflowInfo, detailed bool, indent int) string {
	var lines []string
	indentStr := strings.Repeat("  ", indent)

	for _, workflow := range workflows {
		status := "active"
		if !workflow.Visible {
			status = "hidden"
		}

		experimental := ""
		if workflow.Experimental {
			experimental = " (experimental)"
		}

		lines = append(lines, fmt.Sprintf("%s• %s [%s]%s", indentStr, workflow.Command, status, experimental))

		if detailed && len(workflow.Flags) > 0 {
			lines = append(lines, fmt.Sprintf("%s  Flags: %s", indentStr, strings.Join(workflow.Flags, ", ")))
		}
	}

	return strings.Join(lines, "\n")
}

// createWorkflowListData creates a new workflow.Data object for workflow list
func createWorkflowListData(data interface{}, contentType string, logger *zerolog.Logger, config configuration.Configuration) workflow.Data {
	return workflow.NewData(
		// use new type identifier when creating new data
		workflow.NewTypeIdentifier(WORKFLOWID_TOOLS_WORKFLOW_LIST, toolsWorkflowListName),
		contentType,
		data,
		workflow.WithLogger(logger),
		workflow.WithConfiguration(config),
	)
}
