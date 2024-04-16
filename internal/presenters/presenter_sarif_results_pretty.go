package presenters

import (
	"bytes"
	_ "embed"
	"fmt"
	"slices"
	"strings"
	"text/template"

	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
)

//go:embed test_results.gotmpl
var templateString string

type Finding struct {
	ID            string
	ColorCode     string
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
	for i, run := range input.Runs {
		for j, result := range run.Results {
			severity := "n/a"
			severityLevel := 0
			colorCode := ""
			var rule sarif.Rule
			for _, ruleItem := range run.Tool.Driver.Rules {
				if ruleItem.ID == result.RuleID {
					rule = ruleItem
					break
				}
			}

			if result.Level == "note" {
				severity = "LOW"
			} else if result.Level == "warning" {
				severity = "MEDIUM"
				severityLevel = 1
				colorCode = "\u001B[33m"
			} else if result.Level == "error" {
				severity = "HIGH"
				severityLevel = 2
				colorCode = "\u001B[31m"
			}

			var title string
			if rule.ShortDescription.Text != "" {
				title = rule.ShortDescription.Text
			} else {
				title = rule.Name
			}

			findings = append(findings, Finding{
				ID:            result.RuleID,
				ColorCode:     colorCode,
				SeverityLevel: severityLevel,
				Severity:      severity,
				Title:         title,
				Path:          result.Locations[0].PhysicalLocation.ArtifactLocation.URI,
				Line:          result.Locations[0].PhysicalLocation.Region.StartLine,
				Message:       result.Message.Text,
			})
			fmt.Printf("Run %d, Result %d: %s\n", i, j, result.Level)
		}
	}
	return findings
}

type TestMeta struct {
	OrgName  string
	TestPath string
}

type templateData struct {
	Findings []Finding
	Summary  string
	Meta     TestMeta
}

func PresenterSarifResultsPretty(input sarif.SarifDocument, meta TestMeta) (string, error) {
	buff := &bytes.Buffer{}
	tmpl, err := template.New("test_results").Parse(templateString)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	findings := convertSarifToFindingsList(input)

	err = tmpl.Execute(buff, templateData{
		Findings: SortFindings(findings),
		Summary:  presenterSummary(code_workflow.CreateCodeSummary(&input), meta),
		Meta:     meta,
	})

	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buff.String(), nil
}

func presenterSummary(summary *json_schemas.TestSummary, meta TestMeta) string {
	var buff bytes.Buffer
	var summaryTemplate = template.Must(template.New("summary").Parse(`Test Summary

Organization:      {{ .Org }}
Test type:         {{ .Type }}
Project path:      {{ .TestPath }}

Total issues:   {{ .TotalIssueCount }}
{{ if .TotalIssueCount }}Ignored issues: 0
Open issues:    {{ .OpenIssueCountWithSeverities }}
{{ end }}`))

	totalIssueCount := 0
	openIssueCount := 0
	ignoredIssueCount := 0
	openIssueLabelledCount := ""

	slices.Reverse(summary.SeverityOrderAsc)

	for _, severity := range summary.SeverityOrderAsc {
		for _, result := range summary.Results {
			if result.Severity == severity {
				totalIssueCount += result.Total
				openIssueCount += result.Open
				ignoredIssueCount += result.Ignored
				openIssueLabelledCount += fmt.Sprintf(" %d %s ", result.Open, strings.ToUpper(result.Severity))
			}
		}
	}

	openIssueCountWithSeverities := fmt.Sprintf("%d [%s]", openIssueCount, openIssueLabelledCount)

	err := summaryTemplate.Execute(&buff, struct {
		Org                          string
		TestPath                     string
		Type                         string
		TotalIssueCount              int
		OpenIssueCountWithSeverities string
	}{
		Org:                          meta.OrgName,
		TestPath:                     meta.TestPath,
		Type:                         "Static code analysis",
		TotalIssueCount:              totalIssueCount,
		OpenIssueCountWithSeverities: openIssueCountWithSeverities,
	})
	if err != nil {
		return fmt.Sprintf("failed to execute summary template: %v", err)
	}

	return buff.String()
}

func SummariseFindings(findings []Finding) FindingsSummary {
	summary := FindingsSummary{
		High:   0,
		Medium: 0,
		Low:    0,
	}

	for _, finding := range findings {
		if finding.Severity == "HIGH" {
			summary.High++
		} else if finding.Severity == "MEDIUM" {
			summary.Medium++
		} else if finding.Severity == "LOW" {
			summary.Low++
		}
	}

	return summary
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
