package workflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension/connectivity"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	connectivityCheckWorkflowName = "connectivity-check"
	jsonFlag                      = "json"
	noColorFlag                   = "no-color"
	timeoutFlag                   = "timeout"
)

// Define workflow identifier
var WORKFLOWID_CONNECTIVITY_CHECK workflow.Identifier = workflow.NewWorkflowIdentifier(connectivityCheckWorkflowName)

// InitConnectivityCheckWorkflow initializes the connectivity check workflow
func InitConnectivityCheckWorkflow(engine workflow.Engine) error {
	// Initialize workflow configuration
	config := pflag.NewFlagSet(connectivityCheckWorkflowName, pflag.ExitOnError)

	// Add flags
	config.Bool(jsonFlag, false, "Output results in JSON format")
	config.Bool(noColorFlag, false, "Disable colored output")
	config.Int(timeoutFlag, 10, "Timeout in seconds for each connection test")

	// Register workflow with engine
	_, err := engine.Register(WORKFLOWID_CONNECTIVITY_CHECK, workflow.ConfigurationOptionsFromFlagset(config), connectivityCheckEntryPoint)
	return err
}

// connectivityCheckEntryPoint is the entry point for the connectivity check workflow
func connectivityCheckEntryPoint(invocationCtx workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	// Get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	networkAccess := invocationCtx.GetNetworkAccess()

	// Create connectivity checker
	checker := connectivity.NewChecker(networkAccess, logger, config)

	// Log start of connectivity check
	logger.Info().Msg("Starting Snyk connectivity check")

	// Perform connectivity check
	result, err := checker.CheckConnectivity()
	if err != nil {
		return nil, fmt.Errorf("failed to perform connectivity check: %w", err)
	}

	// Output results based on format
	if config.GetBool(jsonFlag) {
		// JSON output
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal results to JSON: %w", err)
		}

		// Create workflow data for JSON output
		outputData := createWorkflowData(jsonData, "application/json", logger, config)
		return []workflow.Data{outputData}, nil
	} else {
		// Human-readable output
		var buf bytes.Buffer
		useColor := !config.GetBool(noColorFlag) && isTerminal()
		formatter := connectivity.NewFormatter(&buf, useColor)

		if err := formatter.FormatResult(result); err != nil {
			return nil, fmt.Errorf("failed to format results: %w", err)
		}

		// Don't write to UI directly when integrated with CLI - the workflow engine handles output
		// The workflow data will be displayed by the CLI framework

		// Create workflow data for text output
		outputData := createWorkflowData(buf.Bytes(), "text/plain", logger, config)
		return []workflow.Data{outputData}, nil
	}
}

// createWorkflowData creates a new workflow.Data object
func createWorkflowData(data interface{}, contentType string, logger *zerolog.Logger, config configuration.Configuration) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_CONNECTIVITY_CHECK, connectivityCheckWorkflowName),
		contentType,
		data,
		workflow.WithLogger(logger),
		workflow.WithConfiguration(config),
	)
}

// isTerminal checks if stdout is a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
