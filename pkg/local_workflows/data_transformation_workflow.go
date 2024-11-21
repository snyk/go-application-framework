package localworkflows

import (
	"encoding/json"
	"fmt"
	"strings"

	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/pkg/encoding/json"
	"github.com/spf13/pflag"

	cueutil "github.com/snyk/go-application-framework/internal/cueutils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	DataTransformationWorkflowName = "datatransformation"
)

var WORKFLOWID_DATATRANSFORMATION = workflow.NewWorkflowIdentifier(DataTransformationWorkflowName)

func InitDataTransformationWorkflow(engine workflow.Engine) error {
	flags := pflag.NewFlagSet(DataTransformationWorkflowName, pflag.ExitOnError)
	_, err := engine.Register(WORKFLOWID_DATATRANSFORMATION, workflow.ConfigurationOptionsFromFlagset(flags), dataTransformationEntryPoint)

	return err
}

func dataTransformationEntryPoint(invocationCtx workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	ff_transform_enabled := config.GetBool(configuration.FF_TRANSFORMATION_WORKFLOW)
	output = input

	if !ff_transform_enabled {
		return output, nil
	}

	progress := invocationCtx.GetUserInterface().NewProgressBar()
	progress.SetTitle("Transforming data")
	progressError := progress.UpdateProgress(ui.InfiniteProgress)
	if progressError != nil {
		logger.Err(progressError).Msgf("Error when setting progress")
	}

	defer func() {
		localError := progress.Clear()
		if localError != nil {
			logger.Err(localError).Msgf("Error when clearing progress")
		}
	}()

	var findingsModel local_models.LocalFinding

	var sarifInput workflow.Data
	var summaryInput workflow.Data
	var contentLocation string

	for i, data := range input {
		if strings.HasPrefix(data.GetContentType(), content_type.SARIF_JSON) {
			sarifInput = data
			contentLocation = input[i].GetContentLocation()
		}

		if strings.HasPrefix(data.GetContentType(), content_type.TEST_SUMMARY) {
			output = []workflow.Data{data}
			summaryInput = data
		}
	}
	if sarifInput == nil || summaryInput == nil {
		logger.Trace().Msg("incomplete input data for transformation")
		return input, nil
	}

	summary_bytes, ok := summaryInput.GetPayload().([]byte)
	if !ok {
		logger.Err(nil).Msg("summary payload is not a byte array")
		return input, nil
	}
	sarif_bytes, ok := sarifInput.GetPayload().([]byte)
	if !ok {
		return input, err
	}

	findingsModel, err = TransformToLocalFindingModel(sarif_bytes, summary_bytes)
	if err != nil {
		logger.Err(err).Msg(err.Error())
		return input, err
	}

	bytes, err := json.Marshal(findingsModel)
	if err != nil {
		return input, err
	}

	d := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_DATATRANSFORMATION, DataTransformationWorkflowName),
		content_type.LOCAL_FINDING_MODEL,
		bytes, workflow.WithConfiguration(config), workflow.WithLogger(logger), workflow.WithInputData(summaryInput))
	d.SetContentLocation(contentLocation)
	output = append(output, d)

	return output, nil
}

func TransformToLocalFindingModel(sarifBytes []byte, summaryBytes []byte) (localFinding local_models.LocalFinding, err error) {
	var testSummary json_schemas.TestSummary
	err = json.Unmarshal(summaryBytes, &testSummary)
	if err != nil {
		return localFinding, err
	}

	input, errUnJson := cuejson.Unmarshal(sarifBytes)
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

	localFinding.Summary.Path = testSummary.Path
	localFinding.Summary.Artifacts = testSummary.Artifacts
	localFinding.Summary.Type = testSummary.Type
	localFinding.Summary.Counts.CountKeyOrderAsc.Severity = testSummary.SeverityOrderAsc
	localFinding.Summary.Counts.Count = 0
	localFinding.Summary.Counts.CountAdjusted = 0
	localFinding.Summary.Counts.CountSuppressed = 0

	for _, summaryResults := range testSummary.Results {
		localFinding.Summary.Counts.CountBy.Severity[summaryResults.Severity] = uint32(summaryResults.Total)
		localFinding.Summary.Counts.CountByAdjusted.Severity[summaryResults.Severity] = uint32(summaryResults.Open)
		localFinding.Summary.Counts.CountBySuppressed.Severity[summaryResults.Severity] = uint32(summaryResults.Ignored)

		localFinding.Summary.Counts.CountAdjusted += localFinding.Summary.Counts.CountByAdjusted.Severity[summaryResults.Severity]
		localFinding.Summary.Counts.CountSuppressed += uint32(summaryResults.Ignored)
		localFinding.Summary.Counts.Count += uint32(summaryResults.Total)
	}

	return localFinding, nil
}
