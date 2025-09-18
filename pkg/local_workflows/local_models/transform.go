package local_models

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	"github.com/snyk/go-application-framework/pkg/configuration"
	sarif2 "github.com/snyk/go-application-framework/pkg/utils/sarif"

	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
)

const (
	DefaultSuppressionExpiration = "never"
)

func TransformToLocalFindingModelFromSarif(sarifDoc *sarif.SarifDocument, testSummary *json_schemas.TestSummary) (localFinding LocalFinding, err error) {
	localFinding.Links = make(map[string]string)
	localFinding.Summary = transformTestSummary(testSummary, sarifDoc)
	var rules []TypesRules
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

func mapFindings(sarifDoc *sarif.SarifDocument) ([]FindingResource, error) {
	if len(sarifDoc.Runs) == 0 {
		return []FindingResource{}, nil
	}

	var findings []FindingResource
	for _, res := range sarifDoc.Runs[0].Results {
		var shortDescription string
		if len(sarifDoc.Runs[0].Tool.Driver.Rules) > res.RuleIndex && res.RuleIndex >= 0 {
			shortDescription = sarifDoc.Runs[0].Tool.Driver.Rules[res.RuleIndex].ShortDescription.Text
		}

		fingerprints, err := mapFingerprints(res.Fingerprints)
		if err != nil {
			return nil, fmt.Errorf("failed to map fingerprints: %w", err)
		}
		opts := []FindingResourceOption{}
		codeflows := mapCodeFlows(res)
		locations := mapLocations(res)
		if res.Properties.Policy != nil {
			policy := &TypesPolicyv1{
				OriginalLevel:    &res.Properties.Policy.OriginalLevel,
				OriginalSeverity: &res.Properties.Policy.OriginalSeverity,
				Severity:         &res.Properties.Policy.Severity,
			}
			opts = append(opts, WithPolicy(policy))
		}

		opts = append(opts,
			WithRating(CreateFindingRating(res)),
			WithCodeFlows(&codeflows),
			WithSuggestions(&[]Suggestion{}),
			WithLocations(&locations),
			WithSuppression(mapSuppressions(res)),
		)

		finding := NewFindingResource(
			&TypesReferenceId{
				Identifier: res.RuleID,
				Index:      res.RuleIndex,
			},
			fingerprints,
			TypesComponent{
				Name:     ".",
				ScanType: "sast",
			},
			&res.Properties.IsAutofixable,
			TypesFindingMessage{
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

func mapRules(sarifRule sarif.Rule) TypesRules {
	return NewTypesRules(
		sarifRule.ID,
		sarifRule.Name,
		sarifRule.ShortDescription.Text,
		sarifRule.DefaultConfiguration.Level,
		sarifRule.Help.Markdown,
		sarifRule.Help.Text,
		WithCategories(sarifRule.Properties.Categories),
		WithCwe(sarifRule.Properties.Cwe),
		WithExampleCommitDescriptions(sarifRule.Properties.ExampleCommitDescriptions),
		WithExampleCommitFixes(CreateExampleCommitFixes(sarifRule)),
		WithPrecision(sarifRule.Properties.Precision),
		WithRepoDatasetSize(sarifRule.Properties.RepoDatasetSize),
		WithTags(sarifRule.Properties.Tags),
	)
}

func mapSuppressions(res sarif.Result) *TypesSuppression {
	suppression, status := sarif2.GetHighestSuppression(res.Suppressions)
	if suppression == nil {
		return nil
	}
	ignored_email := ""
	if suppression.Properties.IgnoredBy.Email != nil {
		ignored_email = *suppression.Properties.IgnoredBy.Email
	}
	var id *string
	if suppression.Guid != "" {
		id = &suppression.Guid
	}
	return &TypesSuppression{
		Id: id,
		Details: &TypesSuppressionDetails{
			Category:   string(suppression.Properties.Category),
			Expiration: suppression.Properties.Expiration,
			IgnoredOn:  suppression.Properties.IgnoredOn,
			IgnoredBy: TypesUser{
				Name:  suppression.Properties.IgnoredBy.Name,
				Email: ignored_email,
			},
		},
		Justification: &suppression.Justification,
		Status:        TypesSuppressionStatus(status),
	}
}

func createFingerprint(scheme string, value string) (Fingerprint, error) {
	var fp Fingerprint
	raw := []byte(`{"scheme":"` + scheme + `","value":"` + value + `"}`)
	err := json.Unmarshal(raw, &fp)
	return fp, err
}

func mapFingerprints(sfp sarif.Fingerprints) ([]Fingerprint, error) {
	var fingerprints []Fingerprint

	schemeToValue := map[string]string{
		string(Identity):                   sfp.Identity,
		string(CodeSastV0):                 sfp.Num0,
		string(CodeSastV1):                 sfp.Num1,
		string(Snykassetfindingv1):         sfp.SnykAssetFindingV1,
		string(Snykorgrepositoryfindingv1): sfp.SnykOrgRepositoryFindingV1,
		string(Snykorgprojectfindingv1):    sfp.SnykOrgProjectFindingV1,
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

func createLocation(location sarif.PhysicalLocation) IoSnykReactiveFindingSourceLocation {
	return IoSnykReactiveFindingSourceLocation{
		Filepath:            location.ArtifactLocation.URI,
		OriginalStartLine:   location.Region.StartLine,
		OriginalEndLine:     location.Region.EndLine,
		OriginalStartColumn: location.Region.StartColumn,
		OriginalEndColumn:   location.Region.EndColumn,
	}
}

func mapCodeFlows(res sarif.Result) []TypesCodeFlow {
	var codeFlows []TypesCodeFlow
	for _, cf := range res.CodeFlows {
		var codeFlow TypesCodeFlow
		for _, tf := range cf.ThreadFlows {
			var threadFlow TypesThreadFlow
			for _, loc := range tf.Locations {
				threadFlow.Locations = append(threadFlow.Locations, createLocation(loc.Location.PhysicalLocation))
			}
			codeFlow.ThreadFlows = append(codeFlow.ThreadFlows, threadFlow)
		}
		codeFlows = append(codeFlows, codeFlow)
	}
	return codeFlows
}

func transformTestSummary(testSummary *json_schemas.TestSummary, sarifDoc *sarif.SarifDocument) TypesFindingsSummary {
	var summary TypesFindingsSummary
	summary.Path = testSummary.Path
	summary.Artifacts = testSummary.Artifacts
	summary.Type = testSummary.Type
	summary.Counts = NewFindingsCounts()
	summary.Counts.CountKeyOrderAsc.Severity = testSummary.SeverityOrderAsc

	for _, summaryResults := range testSummary.Results {
		summary.Counts.CountBy.Severity[summaryResults.Severity] = uint32(summaryResults.Total)
		summary.Counts.CountByAdjusted.Severity[summaryResults.Severity] = uint32(summaryResults.Open)
		summary.Counts.CountBySuppressed.Severity[summaryResults.Severity] = uint32(summaryResults.Ignored)

		summary.Counts.CountAdjusted += summary.Counts.CountByAdjusted.Severity[summaryResults.Severity]
		summary.Counts.CountSuppressed += uint32(summaryResults.Ignored)
		summary.Counts.Count += uint32(summaryResults.Total)
	}

	var coverage []TypesCoverage
	for _, run := range sarifDoc.Runs {
		for _, cov := range run.Properties.Coverage {
			coverage = append(coverage, TypesCoverage{
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

func mapLocations(res sarif.Result) []IoSnykReactiveFindingLocation {
	locations := make([]IoSnykReactiveFindingLocation, len(res.Locations))
	for i, location := range res.Locations {
		loc := createLocation(location.PhysicalLocation)
		locations[i] = IoSnykReactiveFindingLocation{
			SourceLocations: &loc,
		}
	}
	return locations
}

// updateFindingsSummary updates the summary of the findings based on their severity levels
func UpdateFindingSummary(findingsModel *LocalFinding) {
	updatedFindingCounts := NewFindingsCounts()
	updatedFindingCounts.CountKeyOrderAsc = findingsModel.Summary.Counts.CountKeyOrderAsc

	// update FindingsCount with Findings data
	for _, finding := range findingsModel.Findings {
		severity := string(finding.Attributes.Rating.Severity.Value)
		updatedFindingCounts.CountBy.Severity[severity]++
		updatedFindingCounts.Count++

		if finding.Attributes.Suppression != nil {
			updatedFindingCounts.CountBySuppressed.Severity[severity]++
			updatedFindingCounts.CountSuppressed++
		} else {
			updatedFindingCounts.CountByAdjusted.Severity[severity]++
			updatedFindingCounts.CountAdjusted++
		}
	}

	findingsModel.Summary.Counts = updatedFindingCounts
}

func TranslateMetadataToLocalFindingModel(resultMetaData *scan.ResultMetaData, localFindings *LocalFinding, config configuration.Configuration) {
	// if available add a report url to the findings
	if resultMetaData != nil && len(resultMetaData.WebUiUrl) > 0 {
		localFindings.Links[LINKS_KEY_REPORT] = fmt.Sprintf("%s%s", config.GetString(configuration.WEB_APP_URL), resultMetaData.WebUiUrl)
	}

	// if available add a project id to the findings
	if resultMetaData != nil && len(resultMetaData.ProjectId) > 0 {
		localFindings.Links["projectid"] = resultMetaData.ProjectId
	}

	// if available add a project id to the findings
	if resultMetaData != nil && len(resultMetaData.SnapshotId) > 0 {
		localFindings.Links["snapshotid"] = resultMetaData.SnapshotId
	}
}
