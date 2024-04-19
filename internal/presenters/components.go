package presenters

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
)

func RenderFindings(findings []Finding, showIgnored bool, showOpen bool) string {
	if len(findings) == 0 {
		return ""
	}

	response := ""

	if showOpen {
		response += RenderTitle("Open Issues")

		for _, finding := range findings {
			if finding.Ignored {
				continue
			}
			response += RenderFinding(finding)
		}
	}

	if showOpen && showIgnored {
		response += RenderDivider()
	}

	if showIgnored {
		response += RenderTitle("Ignored Issues")

		for _, finding := range findings {
			if !finding.Ignored {
				continue
			}
			response += RenderFinding(finding)
		}

		response += RenderTip("Ignores are currently managed in the Snyk Web UI.\nTo edit or remove the ignore please go to: https://app.snyk.io/") + "\n"
	}

	return response
}

func RenderFinding(finding Finding) string {
	ignoredProperties := "\n"
	titlePrefix := "✗ "

	if finding.Ignored {
		titlePrefix = "! [ IGNORED ] "
		ignoredProperties = getIgnoredProperties(finding, ignoredProperties)
	}

	return strings.Join([]string{
		fmt.Sprintf(" %s %s",
			renderInSeverityColor(finding.Severity, fmt.Sprintf("%s[%s]", titlePrefix, strings.ToUpper(finding.Severity))),
			renderBold(finding.Title),
		),
		fmt.Sprintf("   Path: %s, line %d", finding.Path, finding.Line),
		fmt.Sprintf("   Info: %s", finding.Message),
		ignoredProperties,
	}, "\n")
}

func RenderDivider() string {
	return "─────────────────────────────────────────────────────\n"
}

func RenderTitle(str string) string {
	return fmt.Sprintf("\n%s\n\n", renderBold(str))
}

func RenderTip(str string) string {
	return fmt.Sprintf("\n💡 Tip\n\n%s", str)
}

func RenderSummary(summary *json_schemas.TestSummary, meta TestMeta) string {
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
