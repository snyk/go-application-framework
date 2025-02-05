package localworkflows

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/snyk/code-client-go/sarif"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/utils/findings"
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
		logger.Info().Msg("Data transformation workflow is disabled")
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

	findingsModel, err = TransformSarifToLocalFindingModel(sarif_bytes, summary_bytes)
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

func TransformSarifToLocalFindingModel(sarifBytes []byte, summaryBytes []byte) (localFinding local_models.LocalFinding, err error) {
	var testSummary json_schemas.TestSummary
	err = json.Unmarshal(summaryBytes, &testSummary)
	if err != nil {
		return localFinding, err
	}

	var sarifDoc sarif.SarifDocument
	err = json.Unmarshal(sarifBytes, &sarifDoc)
	if err != nil {
		return localFinding, fmt.Errorf("failed to unmarshal input: %w", err)
	}

	localFinding.Summary = transformTestSummary(testSummary, sarifDoc)
	var rules []local_models.TypesRules
	for _, run := range sarifDoc.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			localFindingsRule := mapRules(rule)
			rules = append(rules, localFindingsRule)
		}
	}
	localFinding.Rules = rules

	localFinding.Findings, err = mapFindings(sarifDoc)
	if err != nil {
		return localFinding, fmt.Errorf("failed to map findings: %w", err)
	}

	return localFinding, err
}

func mapFindings(sarifDoc sarif.SarifDocument) ([]local_models.FindingResource, error) {
	var findings []local_models.FindingResource
	for _, res := range sarifDoc.Runs[0].Results {
		var shortDescription string
		if len(sarifDoc.Runs[0].Tool.Driver.Rules) > res.RuleIndex && res.RuleIndex >= 0 {
			shortDescription = sarifDoc.Runs[0].Tool.Driver.Rules[res.RuleIndex].ShortDescription.Text
		}

		fingerprints, err := mapFingerprints(res.Fingerprints)
		if err != nil {
			return nil, fmt.Errorf("failed to map fingerprints: %w", err)
		}
		opts := []local_models.FindingResourceOption{}
		codeflows := mapCodeFlows(res)
		locations := mapLocations(res)
		if res.Properties.Policy != nil {
			policy := &local_models.TypesPolicyv1{
				OriginalLevel:    &res.Properties.Policy.OriginalLevel,
				OriginalSeverity: &res.Properties.Policy.OriginalSeverity,
				Severity:         &res.Properties.Policy.Severity,
			}
			opts = append(opts, local_models.WithPolicy(policy))
		}

		opts = append(opts,
			local_models.WithRating(local_models.CreateFindingRating(res)),
			local_models.WithCodeFlows(&codeflows),
			local_models.WithSuggestions(&[]local_models.Suggestion{}),
			local_models.WithLocations(&locations),
			local_models.WithSuppression(mapSuppressions(res)),
		)

		finding := local_models.NewFindingResource(
			&local_models.TypesReferenceId{
				Identifier: res.RuleID,
				Index:      res.RuleIndex,
			},
			fingerprints,
			local_models.TypesComponent{
				Name:     ".",
				ScanType: "sast",
			},
			&res.Properties.IsAutofixable,
			local_models.TypesFindingMessage{
				Header:    shortDescription,
				Text:      res.Message.Text,
				Markdown:  res.Message.Markdown,
				Arguments: res.Message.Arguments,
			},
			opts...,
		)

		findings = append(findings, finding)
	}
	return findings, nil
}

func mapRules(sarifRule sarif.Rule) local_models.TypesRules {
	return local_models.NewTypesRules(
		sarifRule.ID,
		sarifRule.Name,
		sarifRule.ShortDescription.Text,
		sarifRule.DefaultConfiguration.Level,
		sarifRule.Help.Markdown,
		sarifRule.Help.Text,
		local_models.WithCategories(sarifRule.Properties.Categories),
		local_models.WithCwe(sarifRule.Properties.Cwe),
		local_models.WithExampleCommitDescriptions(sarifRule.Properties.ExampleCommitDescriptions),
		local_models.WithExampleCommitFixes(local_models.CreateExampleCommitFixes(sarifRule)),
		local_models.WithPrecision(sarifRule.Properties.Precision),
		local_models.WithRepoDatasetSize(sarifRule.Properties.RepoDatasetSize),
		local_models.WithTags(sarifRule.Properties.Tags),
	)
}

func mapSuppressions(res sarif.Result) *local_models.TypesSuppression {
	if len(res.Suppressions) == 0 {
		return nil
	}
	suppression := res.Suppressions[0]
	expiration := ""
	ignored_email := ""
	if suppression.Properties.Expiration != nil {
		expiration = *suppression.Properties.Expiration
	}
	if suppression.Properties.IgnoredBy.Email != nil {
		ignored_email = *suppression.Properties.IgnoredBy.Email
	}
	return &local_models.TypesSuppression{
		Details: &local_models.TypesSuppressionDetails{
			Category:   string(suppression.Properties.Category),
			Expiration: expiration,
			IgnoredOn:  suppression.Properties.IgnoredOn,
			IgnoredBy: local_models.TypesUser{
				Name:  suppression.Properties.IgnoredBy.Name,
				Email: ignored_email,
			},
		},
		Justification: &suppression.Justification,
		Kind:          "ignored",
	}
}

func createFingerprint(scheme string, value string) (local_models.Fingerprint, error) {
	var fp local_models.Fingerprint
	raw := []byte(`{"scheme":"` + scheme + `","value":"` + value + `"}`)
	err := json.Unmarshal(raw, &fp)
	return fp, err
}

func mapFingerprints(sfp sarif.Fingerprints) ([]local_models.Fingerprint, error) {
	var fingerprints []local_models.Fingerprint

	schemeToValue := map[string]string{
		string(local_models.Identity):                   sfp.Identity,
		string(local_models.CodeSastV0):                 sfp.Num0,
		string(local_models.CodeSastV1):                 sfp.Num1,
		string(local_models.Snykassetfindingv1):         sfp.SnykAssetFindingV1,
		string(local_models.Snykorgrepositoryfindingv1): sfp.SnykOrgRepositoryFindingV1,
		string(local_models.Snykorgprojectfindingv1):    sfp.SnykOrgProjectFindingV1,
	}

	for schemeStr, val := range schemeToValue {
		if val != "" {
			fp, err := createFingerprint(schemeStr, val)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal fingerprint (%s): %w", schemeStr, err)
			}
			fingerprints = append(fingerprints, fp)
		}
	}

	return fingerprints, nil
}

func createLocation(location sarif.PhysicalLocation) local_models.IoSnykReactiveFindingSourceLocation {
	return local_models.IoSnykReactiveFindingSourceLocation{
		Filepath:            location.ArtifactLocation.URI,
		OriginalStartLine:   location.Region.StartLine,
		OriginalEndLine:     location.Region.EndLine,
		OriginalStartColumn: location.Region.StartColumn,
		OriginalEndColumn:   location.Region.EndColumn,
	}
}

func mapCodeFlows(res sarif.Result) []local_models.TypesCodeFlow {
	var codeFlows []local_models.TypesCodeFlow
	for _, cf := range res.CodeFlows {
		var codeFlow local_models.TypesCodeFlow
		for _, tf := range cf.ThreadFlows {
			var threadFlow local_models.TypesThreadFlow
			for _, loc := range tf.Locations {
				threadFlow.Locations = append(threadFlow.Locations, createLocation(loc.Location.PhysicalLocation))
			}
			codeFlow.ThreadFlows = append(codeFlow.ThreadFlows, threadFlow)
		}
		codeFlows = append(codeFlows, codeFlow)
	}
	return codeFlows
}

func transformTestSummary(testSummary json_schemas.TestSummary, sarifDoc sarif.SarifDocument) local_models.TypesFindingsSummary {
	var summary local_models.TypesFindingsSummary
	summary.Path = testSummary.Path
	summary.Artifacts = testSummary.Artifacts
	summary.Type = testSummary.Type
	summary.Counts = findings.NewFindingsCounts()
	summary.Counts.CountKeyOrderAsc.Severity = testSummary.SeverityOrderAsc

	for _, summaryResults := range testSummary.Results {
		summary.Counts.CountBy.Severity[summaryResults.Severity] = uint32(summaryResults.Total)
		summary.Counts.CountByAdjusted.Severity[summaryResults.Severity] = uint32(summaryResults.Open)
		summary.Counts.CountBySuppressed.Severity[summaryResults.Severity] = uint32(summaryResults.Ignored)

		summary.Counts.CountAdjusted += summary.Counts.CountByAdjusted.Severity[summaryResults.Severity]
		summary.Counts.CountSuppressed += uint32(summaryResults.Ignored)
		summary.Counts.Count += uint32(summaryResults.Total)
	}

	var coverage []local_models.TypesCoverage
	for _, run := range sarifDoc.Runs {
		for _, cov := range run.Properties.Coverage {
			coverage = append(coverage, local_models.TypesCoverage{
				Files:       cov.Files,
				IsSupported: cov.IsSupported,
				Lang:        cov.Lang,
				Type:        cov.Type,
			})
		}
	}
	summary.Coverage = coverage

	return summary
}

func mapLocations(res sarif.Result) []local_models.IoSnykReactiveFindingLocation {
	locations := make([]local_models.IoSnykReactiveFindingLocation, len(res.Locations))
	for i, location := range res.Locations {
		loc := createLocation(location.PhysicalLocation)
		locations[i] = local_models.IoSnykReactiveFindingLocation{
			SourceLocations: &loc,
		}
	}
	return locations
}
