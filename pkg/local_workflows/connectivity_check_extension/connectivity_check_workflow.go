package workflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension/connectivity"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	connectivityCheckWorkflowName = "tools.connectivity-check"
	jsonFlag                      = "json"
	noColorFlag                   = "no-color"
	timeoutFlag                   = "timeout"
	maxOrgCountFlag               = "max-org-count"
)

// Define workflow identifier
var WORKFLOWID_CONNECTIVITY_CHECK workflow.Identifier = workflow.NewWorkflowIdentifier(connectivityCheckWorkflowName)

// InitConnectivityCheckWorkflow initializes the connectivity check workflow
func InitConnectivityCheckWorkflow(engine workflow.Engine) error {
	config := pflag.NewFlagSet(connectivityCheckWorkflowName, pflag.ExitOnError)

	config.Bool(jsonFlag, false, "Output results in JSON format")
	config.Bool(noColorFlag, false, "Disable colored output")
	config.Int(timeoutFlag, 10, "Timeout in seconds for each connection test")
	config.Int(maxOrgCountFlag, 100, "Maximum number of organizations to retrieve")

	_, err := engine.Register(WORKFLOWID_CONNECTIVITY_CHECK, workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(config)), connectivityCheckEntryPoint)
	return err
}

// connectivityCheckEntryPoint is the entry point for the connectivity check workflow
func connectivityCheckEntryPoint(invocationCtx workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	networkAccess := invocationCtx.GetNetworkAccess()
	ui := invocationCtx.GetUserInterface()

	// Get additional directories to check from the config
	var additionalDirs []connectivity.UsedDirectory
	additionalDirsConfigVal := config.Get("additional-check-dirs")
	if additionalDirsConfigVal != nil {
		additionalDirsVal, ok := additionalDirsConfigVal.([]connectivity.UsedDirectory)
		if ok {
			additionalDirs = additionalDirsVal
		}
	}

	checker := connectivity.NewChecker(networkAccess, logger, config, additionalDirs, ui)

	logger.Info().Msg("Starting Snyk connectivity check")

	result, err := checker.CheckConnectivity()
	if err != nil {
		return nil, fmt.Errorf("failed to perform connectivity check: %w", err)
	}

	if config.GetBool(jsonFlag) {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal results to JSON: %w", err)
		}

		outputData := createWorkflowData(jsonData, "application/json", logger, config)
		return []workflow.Data{outputData}, nil
	} else {
		// need to format as human-readable text
		var buf bytes.Buffer
		useColor := !config.GetBool(noColorFlag) && isTerminal()

		formatter := connectivity.NewFormatter(&buf, useColor)
		if err := formatter.FormatResult(result); err != nil {
			return nil, fmt.Errorf("failed to format results: %w", err)
		}

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
	return term.IsTerminal(int(os.Stdout.Fd()))
}
