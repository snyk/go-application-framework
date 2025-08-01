package localworkflows

import (
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/code"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
)

const (
	codeWorkflowName = "code.test"
)

func GetCodeFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(codeWorkflowName, pflag.ExitOnError)

	// add flags here
	flagSet.Bool("sarif", false, "Output in sarif format")
	flagSet.Bool("json", false, "Output in json format")
	flagSet.Bool(code_workflow.ConfigurationReportFlag, false, "Share results with the Snyk Web UI")
	flagSet.String(code_workflow.ConfigurationProjectName, "", "The name of the project to test.")
	flagSet.String(configuration.FLAG_REMOTE_REPO_URL, "", "The URL of the remote repository to test.")
	flagSet.String("severity-threshold", "", "Minimum severity level to report (low|medium|high)")
	flagSet.String("sarif-file-output", "", "Save test output in SARIF format directly to the <OUTPUT_FILE_PATH> file, regardless of whether or not you use the --sarif option.")
	flagSet.String("json-file-output", "", "Save test output in JSON format directly to the <OUTPUT_FILE_PATH> file, regardless of whether or not you use the --json option.")
	flagSet.String("project-id", "", "The unique identifier of the project to test.")
	flagSet.String("commit-id", "", "The unique identifier of the commit to test.")
	flagSet.String(code_workflow.ConfigurationTargetName, "", "The name of the target to test.")
	flagSet.String(code_workflow.ConfigurationTargetReference, "", "The reference that differentiates this project, e.g. a branch name or version.")
	flagSet.String("target-file", "", "The path to the target file to test.")

	return flagSet
}

// WORKFLOWID_CODE defines a new workflow identifier
var WORKFLOWID_CODE workflow.Identifier = workflow.NewWorkflowIdentifier(codeWorkflowName)

func getSastSettings(engine workflow.Engine) (*sast_contract.SastResponse, error) {
	config := engine.GetConfiguration()
	org := config.GetString(configuration.ORGANIZATION)
	client := engine.GetNetworkAccess().GetHttpClient()
	url := config.GetString(configuration.API_URL)
	apiClient := api.NewApi(url, client)
	tmp, err := apiClient.GetSastSettings(org)
	if err != nil {
		engine.GetLogger().Err(err).Msg("Failed to access settings.")
		return nil, err
	}

	engine.GetConfiguration().Set(code_workflow.ConfigurationSastSettings, tmp)
	return tmp, nil
}

func getSastSettingsConfig(engine workflow.Engine) configuration.DefaultValueFunction {
	callback := func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		if existingValue != nil {
			return existingValue, nil
		}

		response, err := getSastSettings(engine)
		if err != nil {
			engine.GetLogger().Err(err).Msg("Failed to access settings.")
			return nil, err
		}

		return response, nil
	}
	return callback
}

func getSastEnabled(engine workflow.Engine) configuration.DefaultValueFunction {
	callback := func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		if existingValue != nil {
			return existingValue, nil
		}

		response, err := getSastSettings(engine)
		if err != nil {
			engine.GetLogger().Err(err).Msg("Failed to access settings.")
			return false, err
		}

		return response.SastEnabled, nil
	}
	return callback
}

func getSlceEnabled(engine workflow.Engine) configuration.DefaultValueFunction {
	callback := func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		if existingValue != nil {
			return existingValue, nil
		}

		response, err := getSastSettings(engine)
		if err != nil {
			engine.GetLogger().Err(err).Msg("Failed to access settings.")
			return false, err
		}

		return response.LocalCodeEngine.Enabled, nil
	}
	return callback
}

func useNativeImplementation(config configuration.Configuration, logger *zerolog.Logger, sastEnabled bool) bool {
	useConsistentIgnoresFF := config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES)
	useNativeImplementationFF := config.GetBool(configuration.FF_CODE_NATIVE_IMPLEMENTATION)
	reportEnabled := config.GetBool(code_workflow.ConfigurationReportFlag)
	scleEnabled := config.GetBool(code_workflow.ConfigurarionSlceEnabled)

	nativeImplementationEnabled := (useConsistentIgnoresFF || useNativeImplementationFF) && !scleEnabled

	logger.Debug().Msgf("SAST Enabled:       %v", sastEnabled)
	logger.Debug().Msgf("Report enabled:     %v", reportEnabled)
	logger.Debug().Msgf("SLCE enabled:       %v", scleEnabled)
	logger.Debug().Msgf("FF consistent ignores: %v", useConsistentIgnoresFF)
	logger.Debug().Msgf("FF native implementation: %v", useNativeImplementationFF)

	return nativeImplementationEnabled
}

// InitCodeWorkflow initializes the code workflow before registering it with the engine.
func InitCodeWorkflow(engine workflow.Engine) error {
	// register workflow with engine
	flags := GetCodeFlagSet()
	_, err := engine.Register(WORKFLOWID_CODE, workflow.ConfigurationOptionsFromFlagset(flags), codeWorkflowEntryPoint)

	if err != nil {
		return err
	}

	engine.GetConfiguration().AddDefaultValue(code_workflow.ConfigurationSastSettings, getSastSettingsConfig(engine))
	engine.GetConfiguration().AddDefaultValue(code_workflow.ConfigurationSastEnabled, getSastEnabled(engine))
	engine.GetConfiguration().AddDefaultValue(code_workflow.ConfigurarionSlceEnabled, getSlceEnabled(engine))
	engine.GetConfiguration().AddDefaultValue(code_workflow.ConfigurationTestFLowName, configuration.StandardDefaultValueFunction("cli_test"))
	config_utils.AddFeatureFlagToConfig(engine, configuration.FF_CODE_CONSISTENT_IGNORES, "snykCodeConsistentIgnores")
	config_utils.AddFeatureFlagToConfig(engine, configuration.FF_CODE_NATIVE_IMPLEMENTATION, code_workflow.FfNameNativeImplementation)

	return err
}

// codeWorkflowEntryPoint is the entry point for the code workflow.
// it provides a wrapper for the legacycli workflow
func codeWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	sastEnabled, err := config.GetBoolWithError(code_workflow.ConfigurationSastEnabled)
	if err != nil {
		return result, err
	}

	nativeImplementation := useNativeImplementation(config, logger, sastEnabled)

	if !sastEnabled {
		return result, code.NewFeatureIsNotEnabledError(fmt.Sprintf("Snyk Code is not supported for your current organization: `%s`.", config.GetString(configuration.ORGANIZATION_SLUG)))
	}

	implementationName := "legacy"
	if nativeImplementation {
		implementationName = "native"
	}

	invocationCtx.GetAnalytics().AddExtensionStringValue("implementation", implementationName)
	logger.Debug().Msgf("Implementation: %s", implementationName)

	if nativeImplementation {
		result, err = code_workflow.EntryPointNative(invocationCtx)
	} else {
		result, err = code_workflow.EntryPointLegacy(invocationCtx)
	}

	return result, err
}
