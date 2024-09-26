package localworkflows

import (
	"encoding/json"
	"fmt"
	"strings"

	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/pkg/encoding/json"
	cueutil "github.com/snyk/go-application-framework/internal/cueutils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	DataTransformationWorkflowName = "datatransformation"
)

var WORKFLOWID_DATATRANSFORMATION = workflow.NewWorkflowIdentifier(DataTransformationWorkflowName)

func InitDataTransformationWorkflow(engine workflow.Engine) error {
	flags := pflag.NewFlagSet(DataTransformationWorkflowName, pflag.ExitOnError)
	_, err := engine.Register(WORKFLOWID_DATATRANSFORMATION, workflow.ConfigurationOptionsFromFlagset(flags), dataTransformationEntryPoint)

	engine.GetConfiguration().AddDefaultValue(configuration.FF_TRANSFORMATION_WORKFLOW, configuration.StandardDefaultValueFunction(false))
	return err
}
func testSeverity(severity string) func(json_schemas.TestSummaryResult) bool {
	return func(s json_schemas.TestSummaryResult) bool {
		return s.Severity == severity
	}
}
func filter[T any](ss []T, test func(T) bool) (ret []T) {
	for _, s := range ss {
		if test(s) {
			ret = append(ret, s)
		}
	}
	return
}
func insertSummary(summary json_schemas.TestSummary, localFinding *local_models.LocalFinding) {
	localFinding.Summary.Counts = local_models.IoSnykApiCommonCollectionCounts{
		Count: uint32(summary.Artifacts),
		CountBy: map[string]map[string]uint32{
			"severity": {
				"high":   uint32(len(filter(summary.Results, testSeverity("high")))),
				"medium": uint32(len(filter(summary.Results, testSeverity("medium")))),
				"low":    uint32(len(filter(summary.Results, testSeverity("low")))),
			},
		},
	}

}

func dataTransformationEntryPoint(invocationCtx workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	ff_transform_enabled := config.GetBool(configuration.FF_TRANSFORMATION_WORKFLOW)
	output = input

	logger.Println("dataTransformation workflow start")

	if !ff_transform_enabled {
		return output, nil
	}

	var findingsModel local_models.LocalFinding
	var summary json_schemas.TestSummary

	for _, data := range input {
		if strings.HasPrefix(data.GetContentType(), content_type.SARIF_JSON) {
			// process input
			findingsModel, err = transformSarifData(data)
			if err != nil {
				return output, err
			}
		}

		if strings.HasPrefix(data.GetContentType(), content_type.TEST_SUMMARY) {
			err = json.Unmarshal(data.GetPayload().([]byte), &summary)
			if err != nil {
				logger.Err(err).Msg("Failed to unmarshal test summary")
				return output, err
			}
		}
	}

	// Inject Summary into findingsModel
	// This is a temporary solution to inject the summary into the findings model
	// This will be done in cue in the future
	insertSummary(summary, &findingsModel)

	bytes, err := json.Marshal(findingsModel)
	if err != nil {
		return output, err
	}

	output = append(input, workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_DATATRANSFORMATION, DataTransformationWorkflowName),
		content_type.LOCAL_FINDING_MODEL,
		bytes, workflow.WithConfiguration(config), workflow.WithLogger(logger)))

	return output, nil
}

func transformSarifData(singleData workflow.Data) (localFinding local_models.LocalFinding, err error) {
	jsonData, ok := singleData.GetPayload().([]byte)
	if !ok {
		return localFinding, err
	}

	input, errUnJson := cuejson.Unmarshal(jsonData)
	if errUnJson != nil {
		return localFinding, fmt.Errorf("failed to unmarshal input: %w", err)
	}

	ctx := cuecontext.New()
	sarif2apiTransformer, transformerError := cueutil.NewTransformer(ctx, cueutil.ToTestApiFromSarif)
	if transformerError != nil {
		return localFinding, transformerError
	}

	api2cliTransformer, transformerError := cueutil.NewTransformer(ctx, cueutil.ToCliFromTestApi)
	if transformerError != nil {
		return localFinding, transformerError
	}

	apiOutput, applyError := sarif2apiTransformer.Apply(input)
	if applyError != nil {
		return localFinding, applyError
	}

	cliOutput, applyError := api2cliTransformer.ApplyValue(apiOutput)
	if applyError != nil {
		return localFinding, applyError
	}

	// Gate with validation before encoding?
	encodeErr := cliOutput.Decode(&localFinding)

	if encodeErr != nil {
		return localFinding, fmt.Errorf("failed to convert to type: %w", encodeErr)
	}

	return localFinding, nil
}
