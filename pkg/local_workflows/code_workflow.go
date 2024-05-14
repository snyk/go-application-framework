package localworkflows

import (
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
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

func getSastEnabled(engine workflow.Engine) configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
		if existingValue == nil {
			apiClient := api.NewApiInstance()
			client := engine.GetNetworkAccess().GetHttpClient()
			url := engine.GetConfiguration().GetString(configuration.API_URL)
			org := engine.GetConfiguration().GetString(configuration.ORGANIZATION)
			apiClient.Init(url, client)
			response, err := apiClient.GetSastSettings(org)
			if err != nil {
				engine.GetLogger().Err(err).Msg("Failed to access settings.")
				return false
			}

			return response.SastEnabled
		} else {
			return existingValue
		}
	}
	return callback
}

// InitCodeWorkflow initializes the code workflow before registering it with the engine.
func InitCodeWorkflow(engine workflow.Engine) error {
	// register workflow with engine
	flags := GetCodeFlagSet()
	_, err := engine.Register(WORKFLOWID_CODE, workflow.ConfigurationOptionsFromFlagset(flags), codeWorkflowEntryPoint)

	if err != nil {
		return err
	}

	engine.GetConfiguration().AddDefaultValue(ConfigurationSastEnabled, getSastEnabled(engine))

	return err
}

// codeWorkflowEntryPoint is the entry point for the code workflow.
// it provides a wrapper for the legacycli workflow
func codeWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	sastEnabled := config.GetBool(ConfigurationSastEnabled)
	ignoresFeatureFlag := config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES)
	reportEnabled := config.GetBool("report")

	logger.Debug().Msg("code workflow start")
	logger.Debug().Msgf("SAST Enabled:       %v", sastEnabled)
	logger.Debug().Msgf("Consistent Ignores: %v", ignoresFeatureFlag)
	logger.Debug().Msgf("Report enabled:     %v", reportEnabled)

	if !sastEnabled {
		err = snyk_errors.Error{
			Title:          "Snyk Code is not supported",
			Classification: "ACTIONABLE",
			Level:          "warning",
			Detail:         "Snyk Code is not supported for org " + config.GetString(configuration.ORGANIZATION) + ": enable in Settings > Snyk Code",
			Links:          []string{"https://docs.snyk.io/scan-using-snyk/snyk-code/configure-snyk-code#enable-snyk-code-in-snyk-web-ui\n"},
		}
		return result, err
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
