package localworkflows

import (
	"encoding/json"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/snyk/code-client-go/sarif"
	"github.com/spf13/pflag"

	sarif_utils "github.com/snyk/go-application-framework/internal/utils/sarif"
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

	var sarifDoc sarif.SarifDocument
	err = json.Unmarshal(sarifBytes, &sarifDoc)
	if err != nil {
		return localFinding, err
	}

	localFinding.Summary = *transformTestSummary(&testSummary, &sarifDoc)

	rules := mapRules(sarifDoc)
	localFinding.Rules = rules

	localFinding.Findings, err = mapFindings(sarifDoc)
	if err != nil {
		return localFinding, err
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

		fingerprints := mapFingerprints(res)

		finding := local_models.FindingResource{
			Attributes: local_models.TypesFindingAttributes{
				ReferenceId: &local_models.TypesReferenceId{
					Identifier: res.RuleID,
					Index:      res.RuleIndex,
				},
				Fingerprint: fingerprints,
				Component: local_models.TypesComponent{
					Name:     ".",
					ScanType: "sast",
				},
				IsAutofixable: &res.Properties.IsAutofixable,
				Message: struct {
					Arguments []string `json:"arguments"`
					Header    string   `json:"header"`
					Markdown  string   `json:"markdown"`
					Text      string   `json:"text"`
				}{
					Header:    shortDescription,
					Text:      res.Message.Text,
					Markdown:  res.Message.Markdown,
					Arguments: res.Message.Arguments,
				},
			},
		}

		if res.Properties.Policy != nil {
			finding.Attributes.Policy = &local_models.TypesPolicyv1{
				OriginalLevel:    &res.Properties.Policy.OriginalLevel,
				OriginalSeverity: &res.Properties.Policy.OriginalSeverity,
				Severity:         &res.Properties.Policy.Severity,
			}
		}

		finding.Attributes.Rating = &local_models.TypesFindingRating{
			Severity: struct {
				OriginalValue *local_models.TypesFindingRatingSeverityOriginalValue `json:"original_value,omitempty"`
				Reason        *local_models.TypesFindingRatingSeverityReason        `json:"reason,omitempty"`
				Value         local_models.TypesFindingRatingSeverityValue          `json:"value"`
			}{
				Value: local_models.TypesFindingRatingSeverityValue(sarif_utils.SarifLevelToSeverity(res.Level)),
			},
		}

		finding.Attributes.Rating.Priority = &local_models.TypesFindingNumericalRating{
			Score: res.Properties.PriorityScore,
			Factors: func() (factors []local_models.RiskFactors) {
				for _, v := range res.Properties.PriorityScoreFactors {
					factor := &local_models.RiskFactors{}
					err := factor.FromTypesVulnerabilityFactRiskFactor(local_models.TypesVulnerabilityFactRiskFactor{
						Name:  v.Type,
						Value: v.Label,
					})
					if err != nil {
						return nil
					}
					factors = append(factors, *factor)
				}
				return factors
			}(),
		}

		finding.Attributes.Locations = &[]local_models.IoSnykReactiveFindingLocation{}
		finding.Attributes.CodeFlows = &[]local_models.TypesCodeFlow{}
		finding.Attributes.Suggestions = &[]local_models.Suggestion{}

		for _, location := range res.Locations {
			var l = local_models.IoSnykReactiveFindingLocation{
				SourceLocations: &local_models.IoSnykReactiveFindingSourceLocation{
					Filepath:            location.PhysicalLocation.ArtifactLocation.URI,
					OriginalStartLine:   location.PhysicalLocation.Region.StartLine,
					OriginalEndLine:     location.PhysicalLocation.Region.EndLine,
					OriginalStartColumn: location.PhysicalLocation.Region.StartColumn,
					OriginalEndColumn:   location.PhysicalLocation.Region.EndColumn,
				},
			}
			*finding.Attributes.Locations = append(*finding.Attributes.Locations, l)
		}

		if len(res.Suppressions) > 0 {
			suppression := res.Suppressions[0]
			expiration := ""
			ignored_email := ""
			if suppression.Properties.Expiration != nil {
				expiration = *suppression.Properties.Expiration
			}
			if suppression.Properties.IgnoredBy.Email != nil {
				ignored_email = *suppression.Properties.IgnoredBy.Email
			}
			var sp = local_models.TypesSuppression{
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
			finding.Attributes.Suppression = &sp
		}

		*finding.Attributes.CodeFlows = mapCodeFlows(res)

		findings = append(findings, finding)
	}
	return findings, nil
}

func mapFingerprints(res sarif.Result) []local_models.Fingerprint {
	var fingerprints []local_models.Fingerprint
	if res.Fingerprints.Identity != "" {
		var fp local_models.Fingerprint
		rawIdentity := []byte(`{"scheme":"` + string(local_models.Identity) + `","value":"` + res.Fingerprints.Identity + `"}`)
		if err := json.Unmarshal(rawIdentity, &fp); err != nil {
			log.Warn().Msg("Failed to unmarshal identity fingerprint")
		} else {
			fingerprints = append(fingerprints, fp)
		}
	}
	if res.Fingerprints.Num0 != "" {
		var fp local_models.Fingerprint
		rawNum0 := []byte(`{"scheme":"` + string(local_models.CodeSastV0) + `","value":"` + res.Fingerprints.Num0 + `"}`)
		if err := json.Unmarshal(rawNum0, &fp); err == nil {
			fingerprints = append(fingerprints, fp)
		}
	}
	if res.Fingerprints.Num1 != "" {
		var fp local_models.Fingerprint
		rawNum1 := []byte(`{"scheme":"` + string(local_models.CodeSastV1) + `","value":"` + res.Fingerprints.Num1 + `"}`)
		if err := json.Unmarshal(rawNum1, &fp); err == nil {
			fingerprints = append(fingerprints, fp)
		}
	}
	return fingerprints
}

func mapCodeFlows(res sarif.Result) []local_models.TypesCodeFlow {
	var codeFlows []local_models.TypesCodeFlow
	for _, cf := range res.CodeFlows {
		var codeFlow local_models.TypesCodeFlow
		for _, tf := range cf.ThreadFlows {
			var threadFlow local_models.TypesThreadFlow
			for _, loc := range tf.Locations {
				threadFlow.Locations = append(threadFlow.Locations, local_models.IoSnykReactiveFindingSourceLocation{
					Filepath:            loc.Location.PhysicalLocation.ArtifactLocation.URI,
					OriginalStartLine:   loc.Location.PhysicalLocation.Region.StartLine,
					OriginalEndLine:     loc.Location.PhysicalLocation.Region.EndLine,
					OriginalStartColumn: loc.Location.PhysicalLocation.Region.StartColumn,
					OriginalEndColumn:   loc.Location.PhysicalLocation.Region.EndColumn,
				})
			}
			codeFlow.ThreadFlows = append(codeFlow.ThreadFlows, threadFlow)
		}
		codeFlows = append(codeFlows, codeFlow)
	}
	return codeFlows
}

func mapRules(sarifDoc sarif.SarifDocument) []local_models.TypesRules {
	var rules []local_models.TypesRules
	for _, rule := range sarifDoc.Runs[0].Tool.Driver.Rules {
		rules = append(rules, local_models.TypesRules{
			Id:   rule.ID,
			Name: rule.Name,
			ShortDescription: struct {
				Text string `json:"text"`
			}{
				Text: rule.ShortDescription.Text,
			},
			DefaultConfiguration: struct {
				Level string `json:"level"`
			}{
				Level: rule.DefaultConfiguration.Level,
			},
			Help: struct {
				Markdown string `json:"markdown"`
				Text     string `json:"text"`
			}{
				Markdown: rule.Help.Markdown,
				Text:     rule.Help.Text,
			},
			Properties: struct {
				Categories                []string `json:"categories"`
				Cwe                       []string `json:"cwe"`
				ExampleCommitDescriptions []string `json:"exampleCommitDescriptions"`
				ExampleCommitFixes        []struct {
					CommitUrl string `json:"commitUrl"`
					Lines     []struct {
						Line       string `json:"line"`
						LineNumber int    `json:"lineNumber"`
						Linechange string `json:"linechange"`
					} `json:"lines"`
				} `json:"exampleCommitFixes"`
				Precision       string   `json:"precision"`
				RepoDatasetSize int      `json:"repoDatasetSize"`
				Tags            []string `json:"tags"`
			}{
				Categories:                rule.Properties.Categories,
				Cwe:                       rule.Properties.Cwe,
				ExampleCommitDescriptions: rule.Properties.ExampleCommitDescriptions,
				ExampleCommitFixes: func() []struct {
					CommitUrl string `json:"commitUrl"`
					Lines     []struct {
						Line       string `json:"line"`
						LineNumber int    `json:"lineNumber"`
						Linechange string `json:"linechange"`
					} `json:"lines"`
				} {
					var fixes []struct {
						CommitUrl string `json:"commitUrl"`
						Lines     []struct {
							Line       string `json:"line"`
							LineNumber int    `json:"lineNumber"`
							Linechange string `json:"linechange"`
						} `json:"lines"`
					}
					for _, fix := range rule.Properties.ExampleCommitFixes {
						fixes = append(fixes, struct {
							CommitUrl string `json:"commitUrl"`
							Lines     []struct {
								Line       string `json:"line"`
								LineNumber int    `json:"lineNumber"`
								Linechange string `json:"linechange"`
							} `json:"lines"`
						}{
							CommitUrl: fix.CommitURL,
							Lines: func() []struct {
								Line       string `json:"line"`
								LineNumber int    `json:"lineNumber"`
								Linechange string `json:"linechange"`
							} {
								var lines []struct {
									Line       string `json:"line"`
									LineNumber int    `json:"lineNumber"`
									Linechange string `json:"linechange"`
								}
								for _, line := range fix.Lines {
									lines = append(lines, struct {
										Line       string `json:"line"`
										LineNumber int    `json:"lineNumber"`
										Linechange string `json:"linechange"`
									}{
										Line:       line.Line,
										LineNumber: line.LineNumber,
										Linechange: line.LineChange,
									})
								}
								return lines
							}(),
						})
					}
					return fixes
				}(),
				Precision:       rule.Properties.Precision,
				RepoDatasetSize: rule.Properties.RepoDatasetSize,
				Tags:            rule.Properties.Tags,
			},
		})
	}
	return rules
}

func transformTestSummary(testSummary *json_schemas.TestSummary, sarifDoc *sarif.SarifDocument) *local_models.TypesFindingsSummary {
	var summary local_models.TypesFindingsSummary
	summary.Path = testSummary.Path
	summary.Artifacts = testSummary.Artifacts
	summary.Type = testSummary.Type
	summary.Counts.CountKeyOrderAsc.Severity = testSummary.SeverityOrderAsc
	summary.Counts.Count = 0
	summary.Counts.CountAdjusted = 0
	summary.Counts.CountSuppressed = 0
	summary.Counts.CountBy.Severity = make(map[string]uint32)
	summary.Counts.CountByAdjusted.Severity = make(map[string]uint32)
	summary.Counts.CountBySuppressed.Severity = make(map[string]uint32)
	summary.Counts.CountBy.AdditionalProperties = make(map[string]map[string]uint32)
	summary.Counts.CountByAdjusted.AdditionalProperties = make(map[string]map[string]uint32)
	summary.Counts.CountBySuppressed.AdditionalProperties = make(map[string]map[string]uint32)

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

	return &summary
}
