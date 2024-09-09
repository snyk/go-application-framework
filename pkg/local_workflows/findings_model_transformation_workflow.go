package localworkflows

import (
	"fmt"

	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/pkg/encoding/json"
	cueutil "github.com/snyk/go-application-framework/internal/cue_utils"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	transformationWorkflowName = "internal.transformation.findingsmodel"
)

// WORKFLOWID_FINDINGS_MODDEL_TRANSFORMATION defines a new workflow identifier
var WORKFLOWID_FINDINGS_MODDEL_TRANSFORMATION workflow.Identifier = workflow.NewWorkflowIdentifier(transformationWorkflowName)

// InitCodeWorkflow initializes the code workflow before registering it with the engine.
func InitFindingsModelTransformationWorkflow(engine workflow.Engine) error {
	// register workflow with engine
	flags := pflag.NewFlagSet("", pflag.ExitOnError)
	entry, err := engine.Register(WORKFLOWID_FINDINGS_MODDEL_TRANSFORMATION, workflow.ConfigurationOptionsFromFlagset(flags), findingsModelTransformationWorkflowEntryPoint)
	entry.SetVisibility(false)

	if err != nil {
		return err
	}

	return err
}

// codeWorkflowEntryPoint is the entry point for the code workflow.
// it provides a wrapper for the legacycli workflow
func findingsModelTransformationWorkflowEntryPoint(invocationCtx workflow.InvocationContext, inputs []workflow.Data) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	cuelangIsEnabled := config.GetBool("INTERNAL_SNYK_CUELANG_ENABLED")
	logger.Debug().Msgf("Using Cuelang: %v", cuelangIsEnabled)

	if cuelangIsEnabled {
		for _, singleInput := range inputs {
			if singleInput.GetContentType() == content_type.SARIF_JSON {
				partialResult, sarifError := transformSarifData(singleInput, inputs)
				if sarifError != nil {
					return result, err
				}
				result = append(result, partialResult...)
			}
		}
	} else {
		result = inputs
	}

	return result, err
}

func transformSarifData(singleData workflow.Data, allInputs []workflow.Data) (result []workflow.Data, err error) {
	jsonData := singleData.GetPayload().([]byte)

	input, errUnJson := cuejson.Unmarshal(jsonData)
	if errUnJson != nil {
		return nil, fmt.Errorf("failed to unmarshal input: %w", err)
	}

	ctx := cuecontext.New()
	sarif2apiTransformer, transformerError := cueutil.NewTransformer(ctx, cueutil.ToTestApiFromSarif)
	if transformerError != nil {
		return nil, transformerError
	}

	api2cliTransformer, transformerError := cueutil.NewTransformer(ctx, cueutil.ToCliFromTestApi)
	if transformerError != nil {
		return nil, transformerError
	}

	apiOutput, applyError := sarif2apiTransformer.Apply(input)
	if applyError != nil {
		return nil, applyError
	}

	cliOutput, applyError := api2cliTransformer.ApplyValue(apiOutput)
	if applyError != nil {
		return nil, applyError
	}

	//cliOutputBytes, jsonError := cliOutput.MarshalJSON()
	//if jsonError != nil {
	//	return nil, applyError
	//}

	cueDataObject := workflow.NewDataFromInput(singleData, workflow.NewTypeIdentifier(WORKFLOWID_FINDINGS_MODDEL_TRANSFORMATION, "cuedata"), "application/cuedata", &cliOutput)
	result = append(result, cueDataObject)
	return result, nil
}
