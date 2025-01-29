package local_models

import "github.com/snyk/code-client-go/sarif"

// ExampleCommitFix defines the structure for commit fixes
type ExampleCommitFix struct {
	CommitUrl string `json:"commitUrl"`
	Lines     []struct {
		Line       string `json:"line"`
		LineNumber int    `json:"lineNumber"`
		LineChange string `json:"lineChange"`
	} `json:"lines"`
}

// NewExampleCommitFix creates a new ExampleCommitFix with the provided parameters
func NewExampleCommitFix(commitUrl string, lines []struct {
	Line       string `json:"line"`
	LineNumber int    `json:"lineNumber"`
	LineChange string `json:"lineChange"`
}) ExampleCommitFix {
	return ExampleCommitFix{
		CommitUrl: commitUrl,
		Lines:     lines,
	}
}

// CreateExampleCommitFixes creates a slice of ExampleCommitFix from the provided sarifRule
func CreateExampleCommitFixes(sarifRule sarif.Rule) []ExampleCommitFix {
	var fixes []ExampleCommitFix
	for _, fix := range sarifRule.Properties.ExampleCommitFixes {
		fixes = append(fixes, NewExampleCommitFix(
			fix.CommitURL,
			CreateLines(fix.Lines),
		))
	}
	return fixes
}

// CreateLines creates a slice of lines from the provided lines
func CreateLines(lines []struct {
	Line       string `json:"line"`
	LineNumber int    `json:"lineNumber"`
	LineChange string `json:"lineChange"`
}) []struct {
	Line       string `json:"line"`
	LineNumber int    `json:"lineNumber"`
	LineChange string `json:"lineChange"`
} {
	var result []struct {
		Line       string `json:"line"`
		LineNumber int    `json:"lineNumber"`
		LineChange string `json:"lineChange"`
	}
	for _, line := range lines {
		result = append(result, struct {
			Line       string `json:"line"`
			LineNumber int    `json:"lineNumber"`
			LineChange string `json:"lineChange"`
		}{
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
func WithExampleCommitFixes(fixes []ExampleCommitFix) TypesRulesOption {
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
