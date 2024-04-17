package presenters

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/snyk/code-client-go/sarif"
	sarif_utils "github.com/snyk/go-application-framework/internal/utils/sarif"

	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
)

type Finding struct {
	ID            string
	Severity      string
	SeverityLevel int
	Title         string
	Message       string
	Path          string
	Line          int
}

type FindingsSummary struct {
	High   int
	Medium int
	Low    int
}

func convertSarifToFindingsList(input sarif.SarifDocument) []Finding {
	var findings []Finding
	for _, run := range input.Runs {
		for _, result := range run.Results {
			severity := "n/a"
			severityLevel := 0
			var rule sarif.Rule
			for _, ruleItem := range run.Tool.Driver.Rules {
				if ruleItem.ID == result.RuleID {
					rule = ruleItem
					break
				}
			}

			if result.Level == "note" {
			} else if result.Level == "warning" {
				severityLevel = 1
			} else if result.Level == "error" {
				severityLevel = 2
			}

			severity = sarif_utils.SarifLevelToSeverity(result.Level)

			var title string
			if rule.ShortDescription.Text != "" {
				title = rule.ShortDescription.Text
			} else {
				title = rule.Name
			}

			location := sarif.Location{}
			if len(result.Locations) > 0 {
				location = result.Locations[0]
			}

			findings = append(findings, Finding{
				ID:            result.RuleID,
				SeverityLevel: severityLevel,
				Severity:      severity,
				Title:         title,
				Path:          location.PhysicalLocation.ArtifactLocation.URI,
				Line:          location.PhysicalLocation.Region.StartLine,
				Message:       result.Message.Text,
			})
		}
	}
	return findings
}

type TestMeta struct {
	OrgName  string
	TestPath string
}

func PresenterSarifResultsPretty(input sarif.SarifDocument, meta TestMeta) (string, error) {
	findings := convertSarifToFindingsList(input)
	summary := sarif_utils.CreateCodeSummary(&input)

	str := fmt.Sprintf(`
Testing %s ...
%s
%s
%s
`,
		meta.TestPath,
		renderFindings(SortFindings(findings)),
		presenterSummary(summary, meta),
		getTip(),
	)

	return str, nil
}

func renderFindings(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}

	response := "\nOpen Issues\n\n"

	for _, finding := range findings {
		response += fmt.Sprintf(` %s %s
   Path: %s, line %d
   Info: %s

`, renderInSeverityColor(finding.Severity, fmt.Sprintf("✗ [%s]", strings.ToUpper(finding.Severity))), renderBold(finding.Title), finding.Path, finding.Line, finding.Message)
	}

	return response
}

func getTip() string {
	return `
💡 Tip

To view ignored issues, use the --include-ignores option. To view ignored issues only, use the --only-ignores option.`
}

func presenterSummary(summary *json_schemas.TestSummary, meta TestMeta) string {
	var buff bytes.Buffer
	var summaryTemplate = template.Must(template.New("summary").Parse(`Test Summary

  Organization:      {{ .Org }}
  Test type:         {{ .Type }}
  Project path:      {{ .TestPath }}

  Total issues:   {{ .TotalIssueCount }}{{ if .TotalIssueCount }}
  Ignored issues: {{ .IgnoredIssueCountWithSeverities }} 
  Open issues:    {{ .OpenIssueCountWithSeverities }}{{ end }}`))

	totalIssueCount := 0
	openIssueCount := 0
	ignoredIssueCount := 0
	openIssueLabelledCount := ""
	ignoredIssueLabelledCount := ""

	slices.Reverse(summary.SeverityOrderAsc)

	for _, severity := range summary.SeverityOrderAsc {
		for _, result := range summary.Results {
			if result.Severity == severity {
				totalIssueCount += result.Total
				openIssueCount += result.Open
				ignoredIssueCount += result.Ignored
				openIssueLabelledCount += renderInSeverityColor(severity, fmt.Sprintf(" %d %s ", result.Open, strings.ToUpper(severity)))
				ignoredIssueLabelledCount += renderInSeverityColor(severity, fmt.Sprintf(" %d %s ", result.Ignored, strings.ToUpper(severity)))
			}
		}
	}

	openIssueCountWithSeverities := fmt.Sprintf("%s [%s]", renderBold(strconv.Itoa(openIssueCount)), openIssueLabelledCount)
	ignoredIssueCountWithSeverities := fmt.Sprintf("%s [%s]", renderBold(strconv.Itoa(ignoredIssueCount)), ignoredIssueLabelledCount)
	testType := summary.Type
	if testType == "sast" {
		testType = "Static code analysis"
	}

	err := summaryTemplate.Execute(&buff, struct {
		Org                             string
		TestPath                        string
		Type                            string
		TotalIssueCount                 int
		IgnoreIssueCount                int
		OpenIssueCountWithSeverities    string
		IgnoredIssueCountWithSeverities string
	}{
		Org:                             meta.OrgName,
		TestPath:                        meta.TestPath,
		Type:                            testType,
		TotalIssueCount:                 totalIssueCount,
		IgnoreIssueCount:                ignoredIssueCount,
		OpenIssueCountWithSeverities:    openIssueCountWithSeverities,
		IgnoredIssueCountWithSeverities: ignoredIssueCountWithSeverities,
	})
	if err != nil {
		return fmt.Sprintf("failed to execute summary template: %v", err)
	}

	return boxStyle.Render(buff.String())
}

func SortFindings(findings []Finding) []Finding {
	result := make([]Finding, 0, len(findings))

	result = append(result, findings...)

	slices.SortFunc(result, func(a, b Finding) int {
		if a.SeverityLevel != b.SeverityLevel {
			return a.SeverityLevel - b.SeverityLevel
		}

		return 0
	})

	return result
}
