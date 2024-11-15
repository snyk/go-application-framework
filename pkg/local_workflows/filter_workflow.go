package localworkflows

import (
	"encoding/json"
	"strings"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/utils/findings"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	FilterFindingsWorkflowName = "findings.filter"
)

var WORKFLOWID_FILTER_FINDINGS = workflow.NewWorkflowIdentifier(FilterFindingsWorkflowName)

func InitFilterFindingsWorkflow(engine workflow.Engine) error {
	flags := pflag.NewFlagSet(FilterFindingsWorkflowName, pflag.ExitOnError)
	_, err := engine.Register(WORKFLOWID_FILTER_FINDINGS, workflow.ConfigurationOptionsFromFlagset(flags), filterFindingsEntryPoint)

	return err
}

// applyFilters applies the filters to the findings
// if a finding does not match all of the filters, it is removed
func applyFilters(findingsModel *local_models.LocalFinding, filters []findings.FindingsFilterFunc) {
	filteredFindings := []local_models.FindingResource{}
	for _, finding := range findingsModel.Findings {
		match := true
		for _, filter := range filters {
			if match {
				match = filter(finding)
			} else {
				break
			}
		}
		if match {
			filteredFindings = append(filteredFindings, finding)
		}
	}
	findingsModel.Findings = filteredFindings
}

func filterFindingsEntryPoint(invocationCtx workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	output = []workflow.Data{}

	severityThreshold := strings.ToLower(config.GetString(configuration.FLAG_SEVERITY_THRESHOLD))

	if severityThreshold == "" {
		logger.Println("Severity threshold not set, skipping filter")
		return input, nil
	}

	for _, data := range input {
		if strings.HasPrefix(data.GetContentType(), content_type.LOCAL_FINDING_MODEL) {
			var findingsModel local_models.LocalFinding
			findingsBytes, ok := data.GetPayload().([]byte)
			if !ok {
				var findingsError snyk_errors.Error = snyk_errors.Error{
					Title:          "Invalid Payload Type",
					Classification: "Internal",
					Level:          "warning",
					Detail:         "Failed to filter due to Invalid payload type for local finding model " + data.GetIdentifier().String(),
				}
				logger.Err(findingsError).Msg(findingsError.Error())
				output = append(output, data)
				continue
			}
			err := json.Unmarshal(findingsBytes, &findingsModel)
			if err != nil {
				var unmarshallError snyk_errors.Error = snyk_errors.Error{
					Title:          "Failed to unmarshall findings",
					Classification: "Internal",
					Level:          "warning",
					Detail:         err.Error(),
				}
				logger.Err(unmarshallError).Msg(unmarshallError.Error())
				output = append(output, data)
				continue
			}
			severityOrder := findingsModel.Summary.SeverityOrderAsc
			if !utils.Contains(severityOrder, severityThreshold) {
				var severityError snyk_errors.Error = snyk_errors.Error{
					Title:          "Invalid Severity Threshold",
					Classification: "Internal",
					Level:          "warning",
					Detail:         "Severity threshold " + severityThreshold + " is not valid",
				}
				logger.Err(severityError).Msg(severityError.Error())
				output = append(output, data)
				continue
			}
			applyFilters(&findingsModel, []findings.FindingsFilterFunc{findings.GetSeverityThresholdFilter(severityThreshold, severityOrder)})

			// Update the findings summary after filtering
			findings.UpdateFindingsSummary(&findingsModel)

			filteredFindingsBytes, err := json.Marshal(findingsModel)
			if err != nil {
				var marshallError snyk_errors.Error = snyk_errors.Error{
					Title:          "Failed to marshall findings",
					Classification: "Internal",
					Level:          "warning",
					Detail:         err.Error(),
				}
				logger.Err(marshallError).Msg(marshallError.Error())
				output = append(output, data)
				continue
			}
			output = append(output, workflow.NewData(
				workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS, FilterFindingsWorkflowName),
				content_type.LOCAL_FINDING_MODEL,
				filteredFindingsBytes,
				workflow.WithInputData(data),
			))
		} else {
			output = append(output, data)
		}
	}

	return output, nil
}
