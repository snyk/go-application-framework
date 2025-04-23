package local_models

import (
	"github.com/snyk/code-client-go/sarif"

	sarif_utils "github.com/snyk/go-application-framework/pkg/utils/sarif"
)

func NewFindingsCounts() TypesFindingCounts {
	return TypesFindingCounts{
		CountBy:           TypesFindingCounts_CountBy{Severity: map[string]uint32{}},
		CountByAdjusted:   TypesFindingCounts_CountByAdjusted{Severity: map[string]uint32{}},
		CountBySuppressed: TypesFindingCounts_CountBySuppressed{Severity: map[string]uint32{}},
	}
}

// ExampleCommitFix defines the structure for commit fixes

// NewExampleCommitFix creates a new ExampleCommitFix with the provided parameters
func NewExampleCommitFix(commitUrl string, lines []TypesLine) TypesExampleCommitFix {
	return TypesExampleCommitFix{
		CommitUrl: commitUrl,
		Lines:     lines,
	}
}

// CreateExampleCommitFixes creates a slice of ExampleCommitFix from the provided sarifRule
func CreateExampleCommitFixes(sarifRule sarif.Rule) []TypesExampleCommitFix {
	var fixes []TypesExampleCommitFix
	for _, fix := range sarifRule.Properties.ExampleCommitFixes {
		fixes = append(fixes, NewExampleCommitFix(
			fix.CommitURL,
			CreateLines(fix),
		))
	}
	return fixes
}

// CreateLines creates a slice of lines from the provided lines
func CreateLines(fix sarif.ExampleCommitFix) []TypesLine {
	var result []TypesLine
	for _, line := range fix.Lines {
		result = append(result, TypesLine{
			Line:       line.Line,
			LineNumber: line.LineNumber,
			LineChange: line.LineChange,
		})
	}
	return result
}

// TypesRulesOption defines a type for functional options to customize TypesRules
type TypesRulesOption func(*TypesRules)

// WithCategories sets the Categories field
func WithCategories(categories []string) TypesRulesOption {
	return func(r *TypesRules) {
		r.Properties.Categories = categories
	}
}

// WithCwe sets the Cwe field
func WithCwe(cwe []string) TypesRulesOption {
	return func(r *TypesRules) {
		r.Properties.Cwe = cwe
	}
}

// WithExampleCommitDescriptions sets the ExampleCommitDescriptions field
func WithExampleCommitDescriptions(descriptions []string) TypesRulesOption {
	return func(r *TypesRules) {
		r.Properties.ExampleCommitDescriptions = descriptions
	}
}

// WithExampleCommitFixes sets the ExampleCommitFixes field
func WithExampleCommitFixes(fixes []TypesExampleCommitFix) TypesRulesOption {
	return func(r *TypesRules) {
		r.Properties.ExampleCommitFixes = fixes
	}
}

// WithPrecision sets the Precision field
func WithPrecision(precision string) TypesRulesOption {
	return func(r *TypesRules) {
		r.Properties.Precision = precision
	}
}

// WithRepoDatasetSize sets the RepoDatasetSize field
func WithRepoDatasetSize(size int) TypesRulesOption {
	return func(r *TypesRules) {
		r.Properties.RepoDatasetSize = size
	}
}

// WithTags sets the Tags field
func WithTags(tags []string) TypesRulesOption {
	return func(r *TypesRules) {
		r.Properties.Tags = tags
	}
}

// NewTypesRules creates a new TypesRules with the provided options
func NewTypesRules(id, name, shortDescriptionText, level, helpMarkdown, helpText string, opts ...TypesRulesOption) TypesRules {
	rule := TypesRules{
		Id:   id,
		Name: name,
		ShortDescription: struct {
			Text string `json:"text"`
		}{
			Text: shortDescriptionText,
		},
		DefaultConfiguration: struct {
			Level string `json:"level"`
		}{
			Level: level,
		},
		Help: struct {
			Markdown string `json:"markdown"`
			Text     string `json:"text"`
		}{
			Markdown: helpMarkdown,
			Text:     helpText,
		},
	}

	for _, opt := range opts {
		opt(&rule)
	}

	return rule
}

// FindingResourceOption defines a type for functional options to customize FindingResource
type FindingResourceOption func(*FindingResource)

// WithPolicy sets the Policy field
func WithPolicy(policy *TypesPolicyv1) FindingResourceOption {
	return func(fr *FindingResource) {
		fr.Attributes.Policy = policy
	}
}

// WithRating sets the Rating field
func WithRating(rating *TypesFindingRating) FindingResourceOption {
	return func(fr *FindingResource) {
		fr.Attributes.Rating = rating
	}
}

// WithCodeFlows sets the CodeFlows field
func WithCodeFlows(codeFlows *[]TypesCodeFlow) FindingResourceOption {
	return func(fr *FindingResource) {
		fr.Attributes.CodeFlows = codeFlows
	}
}

// WithSuggestions sets the Suggestions field
func WithSuggestions(suggestions *[]Suggestion) FindingResourceOption {
	return func(fr *FindingResource) {
		fr.Attributes.Suggestions = suggestions
	}
}

// WithLocations sets the Locations field
func WithLocations(locations *[]IoSnykReactiveFindingLocation) FindingResourceOption {
	return func(fr *FindingResource) {
		fr.Attributes.Locations = locations
	}
}

// WithSuppression sets the Suppression field
func WithSuppression(suppression *TypesSuppression) FindingResourceOption {
	return func(fr *FindingResource) {
		fr.Attributes.Suppression = suppression
	}
}

// NewFindingResource creates a new FindingResource with the provided options
func NewFindingResource(referenceId *TypesReferenceId, fingerprints []Fingerprint, component TypesComponent, isAutofixable *bool, message TypesFindingMessage, opts ...FindingResourceOption) FindingResource {
	finding := FindingResource{
		Attributes: TypesFindingAttributes{
			ReferenceId:   referenceId,
			Fingerprint:   fingerprints,
			Component:     component,
			IsAutofixable: isAutofixable,
			Message:       message,
		},
	}

	for _, opt := range opts {
		opt(&finding)
	}

	return finding
}

func CreateFindingRating(res sarif.Result) *TypesFindingRating {
	return &TypesFindingRating{
		Severity: struct {
			OriginalValue *TypesFindingRatingSeverityOriginalValue `json:"original_value,omitempty"`
			Reason        *TypesFindingRatingSeverityReason        `json:"reason,omitempty"`
			Value         TypesFindingRatingSeverityValue          `json:"value"`
		}{
			Value: TypesFindingRatingSeverityValue(sarif_utils.SarifLevelToSeverity(res.Level)),
		},
		Priority: &TypesFindingNumericalRating{
			Score: res.Properties.PriorityScore,
			Factors: func() (factors []RiskFactors) {
				for _, v := range res.Properties.PriorityScoreFactors {
					factor := &RiskFactors{}
					err := factor.FromTypesVulnerabilityFactRiskFactor(
						TypesVulnerabilityFactRiskFactor{
							Name:  v.Type,
							Value: v.Label,
						},
					)
					if err != nil {
						return nil
					}
					factors = append(factors, *factor)
				}
				return factors
			}(),
		},
	}
}
