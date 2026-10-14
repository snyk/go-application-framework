package ufm

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/ufm_helpers"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/utils"
)

func testSarifDoc() *sarif.SarifDocument {
	return &sarif.SarifDocument{
		Runs: []sarif.Run{{
			Tool: sarif.Tool{
				Driver: sarif.Driver{
					Rules: []sarif.Rule{
						{
							ID:   "javascript/NoSqli",
							Name: "NoSqli",
							ShortDescription: sarif.ShortDescription{
								Text: "NoSQL Injection",
							},
							DefaultConfiguration: sarif.DefaultConfiguration{
								Level: "error",
							},
							Help: sarif.Help{
								Markdown: "## Details",
								Text:     "Details text",
							},
							Properties: sarif.RuleProperties{
								Categories: []string{"Security"},
								Cwe:        []string{"CWE-943"},
								Precision:  "very-high",
							},
						},
						{
							ID:   "javascript/XSS",
							Name: "XSS",
							ShortDescription: sarif.ShortDescription{
								Text: "Cross-site Scripting",
							},
							DefaultConfiguration: sarif.DefaultConfiguration{
								Level: "warning",
							},
							Help: sarif.Help{
								Markdown: "## XSS Details",
								Text:     "XSS text",
							},
							Properties: sarif.RuleProperties{
								Cwe: []string{"CWE-79"},
							},
						},
					},
				},
			},
			Results: []sarif.Result{
				{
					RuleID:    "javascript/NoSqli",
					RuleIndex: 0,
					Level:     "error",
					Message: sarif.ResultMessage{
						Text:     "Unsanitized input flows into findOne",
						Markdown: "Unsanitized input **flows** into findOne",
					},
					Locations: []sarif.Location{
						{
							PhysicalLocation: sarif.PhysicalLocation{
								ArtifactLocation: sarif.ArtifactLocation{
									URI: "routes/likeProductReviews.ts",
								},
								Region: sarif.Region{
									StartLine:   18,
									EndLine:     18,
									StartColumn: 26,
									EndColumn:   33,
								},
							},
						},
					},
					Fingerprints: sarif.Fingerprints{
						Identity: "879770c4-b25a-44cd-bba1-1869aa0a3fa7",
						Num0:     "d3e6d95802bfa65cdee1cc840eda6a7b8422f24962e436dd01730e6116e317ec",
					},
				},
				{
					RuleID:    "javascript/XSS",
					RuleIndex: 1,
					Level:     "warning",
					Message: sarif.ResultMessage{
						Text: "XSS vulnerability found",
					},
					Locations: []sarif.Location{
						{
							PhysicalLocation: sarif.PhysicalLocation{
								ArtifactLocation: sarif.ArtifactLocation{
									URI: "routes/index.ts",
								},
								Region: sarif.Region{
									StartLine:   10,
									EndLine:     12,
									StartColumn: 5,
									EndColumn:   20,
								},
							},
						},
					},
					Fingerprints: sarif.Fingerprints{
						Num0: "abc123",
					},
				},
			},
		}},
	}
}

func testSummary() *json_schemas.TestSummary {
	return &json_schemas.TestSummary{
		Results: []json_schemas.TestSummaryResult{
			{Severity: "high", Total: 1, Open: 1, Ignored: 0},
			{Severity: "medium", Total: 1, Open: 1, Ignored: 0},
		},
		SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
		Type:             "sast",
		Artifacts:        4,
		Path:             "/test/path",
	}
}

func TestTransformToUFMFromSarif(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)
	require.NotNil(t, result)

	ctx := context.Background()
	findings, complete, err := result.Findings(ctx)
	require.NoError(t, err)
	assert.True(t, complete)
	assert.Len(t, findings, 2)
}

func TestTransformToUFMFromSarif_FindingAttributes(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)
	first := findings[0]

	assert.NotNil(t, first.Attributes)
	assert.Equal(t, "NoSQL Injection", first.Attributes.Title)
	assert.Equal(t, "Unsanitized input **flows** into findOne", first.Attributes.Description)
	assert.Equal(t, testapi.FindingTypeSast, first.Attributes.FindingType)
	assert.Equal(t, testapi.Severity("high"), first.Attributes.Rating.Severity)
	assert.Equal(t, "879770c4-b25a-44cd-bba1-1869aa0a3fa7", first.Attributes.Key)
}

func TestTransformToUFMFromSarif_FindingLocations(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)
	first := findings[0]

	assert.Len(t, first.Attributes.Locations, 1)

	loc, err := first.Attributes.Locations[0].AsSourceLocation()
	require.NoError(t, err)
	assert.Equal(t, "routes/likeProductReviews.ts", loc.FilePath)
	assert.Equal(t, 18, loc.FromLine)
	assert.Equal(t, 26, *loc.FromColumn)
	assert.Equal(t, 18, *loc.ToLine)
	assert.Equal(t, 33, *loc.ToColumn)
}

func TestTransformToUFMFromSarif_CWEProblems(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)
	first := findings[0]

	require.Len(t, first.Attributes.Problems, 2)

	codeRule, err := first.Attributes.Problems[0].AsSnykCodeRuleProblem()
	require.NoError(t, err)
	assert.Equal(t, "javascript/NoSqli", codeRule.Id)
	assert.Equal(t, "NoSqli", codeRule.Name)

	cwe, err := first.Attributes.Problems[1].AsCweProblem()
	require.NoError(t, err)
	assert.Equal(t, "CWE-943", cwe.Id)
	assert.Equal(t, testapi.Cwe, cwe.Source)
}

func TestTransformToUFMFromSarif_FallbackDescription(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)
	second := findings[1]

	assert.Equal(t, "Cross-site Scripting", second.Attributes.Title)
	assert.Equal(t, "XSS vulnerability found", second.Attributes.Description)
}

func TestTransformToUFMFromSarif_SeverityMapping(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)

	assert.Equal(t, testapi.Severity("high"), findings[0].Attributes.Rating.Severity)
	assert.Equal(t, testapi.Severity("medium"), findings[1].Attributes.Rating.Severity)
}

func TestTransformToUFMFromSarif_SeverityThreshold(t *testing.T) {
	t.Run("filters findings below threshold", func(t *testing.T) {
		result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary(), WithSeverityThreshold("high"))
		require.NoError(t, err)

		findings, _, err := result.Findings(context.Background())
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		assert.Equal(t, testapi.Severity("high"), findings[0].Attributes.Rating.Severity)

		summary := result.GetEffectiveSummary()
		require.NotNil(t, summary)
		assert.Equal(t, uint32(1), summary.Count)
		assert.Equal(t, uint32(1), (*summary.CountBy)["severity"]["high"])
		_, hasMedium := (*summary.CountBy)["severity"]["medium"]
		assert.False(t, hasMedium)
	})

	t.Run("filters every summary, not just the effective one", func(t *testing.T) {
		summary := testSummary()
		summary.Results = []json_schemas.TestSummaryResult{
			{Severity: "high", Total: 3, Open: 1, Ignored: 2},
			{Severity: "medium", Total: 5, Open: 4, Ignored: 1},
		}

		result, err := TransformToUFMFromSarif(testSarifDoc(), summary, WithSeverityThreshold("high"))
		require.NoError(t, err)

		// Sub-threshold severities are gone from the findings, so reporting
		// them in the raw summary would contradict what the caller can see.
		raw := result.GetRawSummary()
		require.NotNil(t, raw)
		_, hasMedium := (*raw.CountBy)["severity"]["medium"]
		assert.False(t, hasMedium, "raw summary still counts medium")
		assert.Equal(t, uint32(3), raw.Count)
	})

	t.Run("keeps all findings when no threshold", func(t *testing.T) {
		result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
		require.NoError(t, err)

		findings, _, err := result.Findings(context.Background())
		require.NoError(t, err)
		assert.Len(t, findings, 2)
	})

	t.Run("filters all findings when threshold above all", func(t *testing.T) {
		result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary(), WithSeverityThreshold("critical"))
		require.NoError(t, err)

		findings, _, err := result.Findings(context.Background())
		require.NoError(t, err)
		assert.Len(t, findings, 0)
	})
}

func TestTransformToUFMFromSarif_EffectiveSummary(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)

	summary := result.GetEffectiveSummary()
	require.NotNil(t, summary)
	assert.Equal(t, uint32(2), summary.Count)

	countBy := *summary.CountBy
	assert.Equal(t, uint32(1), countBy["severity"]["high"])
	assert.Equal(t, uint32(1), countBy["severity"]["medium"])
}

func TestTransformToUFMFromSarif_RawSummary(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)

	summary := result.GetRawSummary()
	require.NotNil(t, summary)
	assert.Equal(t, uint32(2), summary.Count)

	countBy := *summary.CountBy
	assert.Equal(t, uint32(1), countBy["severity"]["high"])
	assert.Equal(t, uint32(1), countBy["severity"]["medium"])
}

func TestTransformToUFMFromSarif_Metadata(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)

	assert.Equal(t, "/test/path", result.GetMetadataValue("path"))
	assert.Equal(t, "sast", result.GetMetadataValue("type"))
	assert.Equal(t, 4, result.GetMetadataValue("artifacts"))
}

func TestTransformToUFMFromSarif_ExecutionState(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)

	assert.Equal(t, testapi.TestExecutionStatesFinished, result.GetExecutionState())
}

func TestTransformToUFMFromSarif_EmptyRuns(t *testing.T) {
	sarifDoc := &sarif.SarifDocument{Runs: []sarif.Run{}}
	summary := testSummary()

	result, err := TransformToUFMFromSarif(sarifDoc, summary)
	require.NoError(t, err)

	ctx := context.Background()
	findings, complete, err := result.Findings(ctx)
	require.NoError(t, err)
	assert.True(t, complete)
	assert.Empty(t, findings)
}

func TestTransformToUFMFromSarif_WithSuppression(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[0].Suppressions = []sarif.Suppression{
		{
			Guid:          "3b3b7c0c-7b1e-4b0e-8b0a-0b0b0b0b0b0b",
			Justification: "Not applicable",
			Status:        sarif.Accepted,
			Properties: sarif.SuppressionProperties{
				Category:  "wont-fix",
				IgnoredOn: "2024-01-15T10:00:00Z",
				IgnoredBy: sarif.IgnoredBy{
					Name:  "Test User",
					Email: utils.Ptr("test@example.com"),
				},
			},
		},
	}

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)

	require.NotNil(t, findings[0].Attributes.Suppression)
	assert.Equal(t, testapi.SuppressionStatusIgnored, findings[0].Attributes.Suppression.Status)
	assert.Equal(t, "Not applicable", *findings[0].Attributes.Suppression.Justification)
	assert.NotNil(t, findings[0].Attributes.Suppression.CreatedAt)

	assert.Nil(t, findings[1].Attributes.Suppression)
}

func TestTransformToUFMFromSarif_SuppressionStatusMapping(t *testing.T) {
	tests := []struct {
		name           string
		sarifStatus    sarif.SuppresionStatus
		expectedStatus testapi.SuppressionStatus
	}{
		{"accepted maps to ignored", sarif.Accepted, testapi.SuppressionStatusIgnored},
		{"under review maps to pending", sarif.UnderReview, testapi.SuppressionStatusPendingIgnoreApproval},
		{"rejected maps to other", sarif.Rejected, testapi.SuppressionStatusOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sarifDoc := testSarifDoc()
			sarifDoc.Runs[0].Results[0].Suppressions = []sarif.Suppression{
				{
					Justification: "test",
					Status:        tt.sarifStatus,
					Properties:    sarif.SuppressionProperties{},
				},
			}

			result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
			require.NoError(t, err)

			ctx := context.Background()
			findings, _, err := result.Findings(ctx)
			require.NoError(t, err)
			require.NotNil(t, findings[0].Attributes.Suppression)
			assert.Equal(t, tt.expectedStatus, findings[0].Attributes.Suppression.Status)
		})
	}
}

func TestTransformToUFMFromSarif_FindingID(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)

	assert.NotNil(t, findings[0].Id)
	assert.Equal(t, "879770c4-b25a-44cd-bba1-1869aa0a3fa7", findings[0].Id.String())

	assert.NotNil(t, findings[1].Id)
}

func TestTransformToUFMFromSarif_FindingID_NoFingerprints_UsesLocation(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[0].Fingerprints = sarif.Fingerprints{}
	sarifDoc.Runs[0].Results[1].Fingerprints = sarif.Fingerprints{}
	sarifDoc.Runs[0].Results[0].RuleID = "same/Rule"
	sarifDoc.Runs[0].Results[1].RuleID = "same/Rule"

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)

	findings, _, err := result.Findings(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.NotEqual(t, findings[0].Id.String(), findings[1].Id.String(),
		"findings with same rule but different locations must have distinct IDs")
}

func TestTransformToUFMFromSarif_KeyFallback(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[1].Fingerprints = sarif.Fingerprints{}

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)

	assert.Equal(t, findings[1].Id.String(), findings[1].Attributes.Key)
}

// Code can report several results with the same "0" fingerprint (same rule and
// line, different column). Each must stay its own issue rather than being merged.
func TestTransformToUFMFromSarif_KeepsResultsSharingPrimaryFingerprint(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[1].RuleID = sarifDoc.Runs[0].Results[0].RuleID
	sarifDoc.Runs[0].Results[1].RuleIndex = sarifDoc.Runs[0].Results[0].RuleIndex
	sarifDoc.Runs[0].Results[1].Fingerprints = sarif.Fingerprints{
		Num0: sarifDoc.Runs[0].Results[0].Fingerprints.Num0,
		Num1: "different-secondary-fingerprint",
	}
	sarifDoc.Runs[0].Results[0].Fingerprints.Identity = ""

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)

	issues, err := testapi.NewIssuesFromTestResult(context.Background(), result)
	require.NoError(t, err)
	assert.Len(t, issues, 2)
}

func TestTransformToUFMFromSarif_KeyFallbackDistinguishesLocations(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[0].Fingerprints = sarif.Fingerprints{}
	sarifDoc.Runs[0].Results[1].Fingerprints = sarif.Fingerprints{}
	sarifDoc.Runs[0].Results[0].RuleID = "same/Rule"
	sarifDoc.Runs[0].Results[1].RuleID = "same/Rule"

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)
	findings, _, err := result.Findings(context.Background())
	require.NoError(t, err)

	require.Len(t, findings, 2)
	assert.NotEqual(t, findings[0].Attributes.Key, findings[1].Attributes.Key)
}

func TestTransformToUFMFromSarif_EffectiveSummaryKeepsUnmappedSeverityWithoutThreshold(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[0].Level = "none"
	summary := testSummary()
	summary.Results = append(summary.Results, json_schemas.TestSummaryResult{Severity: "unmapped", Total: 1, Open: 1})

	result, err := TransformToUFMFromSarif(sarifDoc, summary)
	require.NoError(t, err)

	effective := result.GetEffectiveSummary()
	require.NotNil(t, effective)
	assert.Equal(t, uint32(3), effective.Count)
	assert.Equal(t, uint32(1), (*effective.CountBy)["severity"]["unmapped"])
}

func TestTransformToUFMFromSarif_SummaryWithIgnores(t *testing.T) {
	summary := &json_schemas.TestSummary{
		Results: []json_schemas.TestSummaryResult{
			{Severity: "high", Total: 10, Open: 3, Ignored: 7},
			{Severity: "medium", Total: 5, Open: 1, Ignored: 4},
		},
		Type:      "sast",
		Artifacts: 2,
		Path:      "/path",
	}

	result, err := TransformToUFMFromSarif(testSarifDoc(), summary)
	require.NoError(t, err)

	effective := result.GetEffectiveSummary()
	require.NotNil(t, effective)
	assert.Equal(t, uint32(4), effective.Count)
	assert.Equal(t, uint32(3), (*effective.CountBy)["severity"]["high"])
	assert.Equal(t, uint32(1), (*effective.CountBy)["severity"]["medium"])

	raw := result.GetRawSummary()
	require.NotNil(t, raw)
	assert.Equal(t, uint32(15), raw.Count)
	assert.Equal(t, uint32(10), (*raw.CountBy)["severity"]["high"])
	assert.Equal(t, uint32(5), (*raw.CountBy)["severity"]["medium"])
}

func TestTransformToUFMFromSarif_NilTestSummary(t *testing.T) {
	result, err := TransformToUFMFromSarif(testSarifDoc(), nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Nil(t, result.GetEffectiveSummary())
	assert.Nil(t, result.GetRawSummary())

	ctx := context.Background()
	findings, complete, err := result.Findings(ctx)
	require.NoError(t, err)
	assert.True(t, complete)
	assert.Len(t, findings, 2)
}

func TestTransformToUFMFromSarif_CodeFlows(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[0].CodeFlows = []sarif.CodeFlow{
		{
			ThreadFlows: []sarif.ThreadFlow{
				{
					Locations: []sarif.ThreadFlowLocation{
						{
							Location: sarif.Location{
								PhysicalLocation: sarif.PhysicalLocation{
									ArtifactLocation: sarif.ArtifactLocation{URI: "source.ts"},
									Region:           sarif.Region{StartLine: 5, EndLine: 5, StartColumn: 10, EndColumn: 20},
								},
							},
						},
						{
							Location: sarif.Location{
								PhysicalLocation: sarif.PhysicalLocation{
									ArtifactLocation: sarif.ArtifactLocation{URI: "sink.ts"},
									Region:           sarif.Region{StartLine: 18, EndLine: 18, StartColumn: 26, EndColumn: 33},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)

	require.Len(t, findings[0].Attributes.Evidence, 1)

	execFlow, err := findings[0].Attributes.Evidence[0].AsExecutionFlowEvidence()
	require.NoError(t, err)
	assert.Len(t, execFlow.Flow, 2)
	assert.Equal(t, "source.ts", execFlow.Flow[0].FilePath)
	assert.Equal(t, 5, execFlow.Flow[0].FromLine)
	assert.Equal(t, "sink.ts", execFlow.Flow[1].FilePath)
	assert.Equal(t, 18, execFlow.Flow[1].FromLine)

	assert.Empty(t, findings[1].Attributes.Evidence)
}

func TestTransformToUFMFromSarif_RiskScore(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[0].Properties.PriorityScore = 800

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)

	require.NotNil(t, findings[0].Attributes.Risk.RiskScore)
	assert.Equal(t, uint16(800), findings[0].Attributes.Risk.RiskScore.Value)

	assert.Nil(t, findings[1].Attributes.Risk.RiskScore)
}

func TestTransformToUFMFromSarif_PolicyModifications(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[0].Properties.Policy = &sarif.SnykPolicyV1{
		OriginalLevel:    "error",
		OriginalSeverity: "high",
		Severity:         "low",
	}

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)

	require.NotNil(t, findings[0].Attributes.PolicyModifications)
	mods := *findings[0].Attributes.PolicyModifications
	require.Len(t, mods, 1)
	assert.Equal(t, "/rating/severity", mods[0].Pointer)
	assert.Contains(t, mods[0].Reason, "high")
	assert.Contains(t, mods[0].Reason, "low")

	assert.Nil(t, findings[1].Attributes.PolicyModifications)
}

func TestTransformToUFMFromSarif_FindingExtras(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[0].Properties.IsAutofixable = true
	sarifDoc.Runs[0].Results[0].Message.Arguments = []string{"arg1", "arg2"}

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)

	extras, ok := result.GetMetadataValue(ufm_helpers.MetadataKeyFindingExtras).(map[string]interface{})
	require.True(t, ok)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)

	firstID := findings[0].Id.String()
	firstExtra, ok := extras[firstID].(ufm_helpers.FindingExtra)
	require.True(t, ok)
	assert.True(t, firstExtra.IsAutofixable)
	assert.Equal(t, []string{"arg1", "arg2"}, firstExtra.Arguments)
	assert.Equal(t, "879770c4-b25a-44cd-bba1-1869aa0a3fa7", firstExtra.Fingerprints["identity"])
	assert.Equal(t, "d3e6d95802bfa65cdee1cc840eda6a7b8422f24962e436dd01730e6116e317ec", firstExtra.Fingerprints["0"])

	secondID := findings[1].Id.String()
	secondExtra, ok := extras[secondID].(ufm_helpers.FindingExtra)
	require.True(t, ok)
	assert.False(t, secondExtra.IsAutofixable)
	assert.Nil(t, secondExtra.Arguments)
}

func TestTransformToUFMFromSarif_SuppressionExtras(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Results[0].Suppressions = []sarif.Suppression{
		{
			Guid:          "3b3b7c0c-7b1e-4b0e-8b0a-0b0b0b0b0b0b",
			Justification: "Not applicable",
			Status:        sarif.Accepted,
			Properties: sarif.SuppressionProperties{
				Category:  "wont-fix",
				IgnoredOn: "2024-01-15T10:00:00Z",
				IgnoredBy: sarif.IgnoredBy{
					Name:  "Test User",
					Email: utils.Ptr("test@example.com"),
				},
			},
		},
	}

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)

	ctx := context.Background()
	findings, _, err := result.Findings(ctx)
	require.NoError(t, err)

	extras, ok := result.GetMetadataValue(ufm_helpers.MetadataKeyFindingExtras).(map[string]interface{})
	require.True(t, ok)

	firstID := findings[0].Id.String()
	firstExtra, ok := extras[firstID].(ufm_helpers.FindingExtra)
	require.True(t, ok)
	require.NotNil(t, firstExtra.Suppression)
	assert.Equal(t, "3b3b7c0c-7b1e-4b0e-8b0a-0b0b0b0b0b0b", firstExtra.Suppression.GUID)
	assert.Equal(t, "wont-fix", firstExtra.Suppression.Category)
	assert.Equal(t, "Test User", firstExtra.Suppression.IgnoredBy)
	assert.Equal(t, "test@example.com", firstExtra.Suppression.Email)
}

func TestTransformToUFMFromSarif_CoverageData(t *testing.T) {
	sarifDoc := testSarifDoc()
	sarifDoc.Runs[0].Properties.Coverage = []struct {
		Files       int    `json:"files"`
		IsSupported bool   `json:"isSupported"`
		Lang        string `json:"lang"`
		Type        string `json:"type"`
	}{
		{Files: 10, IsSupported: true, Lang: "javascript", Type: ""},
		{Files: 5, IsSupported: true, Lang: "typescript", Type: ""},
	}

	result, err := TransformToUFMFromSarif(sarifDoc, testSummary())
	require.NoError(t, err)

	coverageSlice, ok := result.GetMetadataValue(ufm_helpers.MetadataKeyCoverage).([]ufm_helpers.Coverage)
	require.True(t, ok)
	assert.Len(t, coverageSlice, 2)
	assert.Equal(t, "javascript", coverageSlice[0].Lang)
	assert.Equal(t, 10, coverageSlice[0].Files)
}

func TestTransformToUFMFromSarif_RealData(t *testing.T) {
	sarifBytes, err := os.ReadFile("../../local_workflows/testdata/sarif-juice-shop.json")
	require.NoError(t, err)
	summaryBytes, err := os.ReadFile("../../local_workflows/testdata/juice-shop-summary.json")
	require.NoError(t, err)

	var sarifDoc sarif.SarifDocument
	require.NoError(t, json.Unmarshal(sarifBytes, &sarifDoc))
	var testSummary json_schemas.TestSummary
	require.NoError(t, json.Unmarshal(summaryBytes, &testSummary))

	result, err := TransformToUFMFromSarif(&sarifDoc, &testSummary)
	require.NoError(t, err)

	findings, complete, err := result.Findings(context.Background())
	require.NoError(t, err)
	assert.True(t, complete)
	assert.Len(t, findings, 278)
	assert.Equal(t, testapi.TestExecutionStatesFinished, result.GetExecutionState())

	countBy := *result.GetEffectiveSummary().CountBy
	assert.Equal(t, uint32(1), countBy["severity"]["critical"])
	assert.Equal(t, uint32(3), countBy["severity"]["high"])
	assert.Equal(t, uint32(1), countBy["severity"]["medium"])
	assert.Equal(t, uint32(0), countBy["severity"]["low"])

	rawCountBy := *result.GetRawSummary().CountBy
	assert.Equal(t, uint32(1), rawCountBy["severity"]["critical"])
	assert.Equal(t, uint32(10), rawCountBy["severity"]["high"])
	assert.Equal(t, uint32(5), rawCountBy["severity"]["medium"])
	assert.Equal(t, uint32(2), rawCountBy["severity"]["low"])
}
