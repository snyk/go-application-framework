package localworkflows

import (
	"github.com/spf13/pflag"

	"github.com/snyk/error-catalog-golang-public/code"
	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	codeWorkflowName         = "code.test"
	ConfigurationSastEnabled = "internal_sast_enabled"
)

func GetCodeFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(codeWorkflowName, pflag.ExitOnError)

	// add flags here
	flagSet.Bool("sarif", false, "Output in sarif format")
	flagSet.Bool("json", false, "Output in json format")
	flagSet.Bool("report", false, "Share results with the Snyk Web UI")
	flagSet.String("severity-threshold", "", "Minimum severity level to report (low|medium|high)")
	flagSet.String("sarif-file-output", "", "Save test output in SARIF format directly to the <OUTPUT_FILE_PATH> file, regardless of whether or not you use the --sarif option.")
	flagSet.String("json-file-output", "", "Save test output in JSON format directly to the <OUTPUT_FILE_PATH> file, regardless of whether or not you use the --json option.")
	flagSet.String("project-name", "", "The name of the project to test.")
	flagSet.String("project-id", "", "The unique identifier of the project to test.")
	flagSet.String("commit-id", "", "The unique identifier of the commit to test.")
	flagSet.String("target-name", "", "The name of the target to test.")
	flagSet.String("target-file", "", "The path to the target file to test.")
	flagSet.String(code_workflow.RemoteRepoUrlFlagname, "", "The URL of the remote repository to test.")
	flagSet.Bool(configuration.FLAG_EXPERIMENTAL, false, "Enable experimental code test command")

	return flagSet
}

// WORKFLOWID_CODE defines a new workflow identifier
var WORKFLOWID_CODE workflow.Identifier = workflow.NewWorkflowIdentifier(codeWorkflowName)

func getSastEnabled(config configuration.Configuration, engine workflow.Engine) (bool, error) {
	enabled := config.GetBool(ConfigurationSastEnabled)
	if enabled {
		return enabled, nil
	}

	client := engine.GetNetworkAccess().GetHttpClient()
	url := engine.GetConfiguration().GetString(configuration.API_URL)
	org := engine.GetConfiguration().GetString(configuration.ORGANIZATION)
	apiClient := api.NewApi(url, client)
	response, err := apiClient.GetSastSettings(org)
	if err != nil {
		engine.GetLogger().Err(err).Msg("Failed to access settings.")
		return false, err
	}

	return response.SastEnabled, nil
}

// InitCodeWorkflow initializes the code workflow before registering it with the engine.
func InitCodeWorkflow(engine workflow.Engine) error {
	// register workflow with engine
	flags := GetCodeFlagSet()
	_, err := engine.Register(WORKFLOWID_CODE, workflow.ConfigurationOptionsFromFlagset(flags), codeWorkflowEntryPoint)

	if err != nil {
		return err
	}

	engine.GetConfiguration().AddDefaultValue(ConfigurationSastEnabled, configuration.StandardDefaultValueFunction(false))
	engine.GetConfiguration().AddDefaultValue(code_workflow.ConfigurationTestFLowName, configuration.StandardDefaultValueFunction("cli_test"))
	config_utils.AddFeatureFlagToConfig(engine, configuration.FF_CODE_CONSISTENT_IGNORES, "snykCodeConsistentIgnores")

	return err
}

// codeWorkflowEntryPoint is the entry point for the code workflow.
// it provides a wrapper for the legacycli workflow
func codeWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	engine := invocationCtx.GetEngine()
	logger := invocationCtx.GetEnhancedLogger()
	
	ignoresFeatureFlag := config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES)
	reportEnabled := config.GetBool("report")
	sastEnabled, err := getSastEnabled(config, engine)
	if err != nil {
		return result, err
	}

	logger.Debug().Msgf("SAST Enabled:       %v", sastEnabled)
	logger.Debug().Msgf("Consistent Ignores: %v", ignoresFeatureFlag)
	logger.Debug().Msgf("Report enabled:     %v", reportEnabled)

	if !sastEnabled {
		return result, code.NewFeatureIsNotEnabledError("Snyk Code is not supported for your current organization.")
	}

	if ignoresFeatureFlag && !reportEnabled {
		logger.Debug().Msg("Implementation: Native")

		unsupportedParameter := []string{"project-name", "project-id", "commit-id", "target-name", "target-file"}
		for _, v := range unsupportedParameter {
			if config.IsSet(v) {
				logger.Warn().Msgf("The parameter \"%s\" is not yet supported in this experimental implementation!", v)
			}
		}

		result, err = code_workflow.EntryPointNative(invocationCtx)
	} else {
		logger.Debug().Msg("Implementation: legacy")
		result, err = code_workflow.EntryPointLegacy(invocationCtx)
	}

	return result, err
}
