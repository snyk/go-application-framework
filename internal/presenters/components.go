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
	titlePrefix := "✗ "

	if finding.Ignored {
		titlePrefix = "! [ IGNORED ] "
	}

	properties := getFormattedProperties(finding.Properties)

	return strings.Join([]string{
		fmt.Sprintf(" %s %s",
			renderInSeverityColor(finding.Severity, fmt.Sprintf("%s[%s]", titlePrefix, strings.ToUpper(finding.Severity))),
			renderBold(finding.Title),
		),
		properties,
	}, "\n")
}

func RenderDivider() string {
	return "─────────────────────────────────────────────────────\n"
}

func RenderTitle(str string) string {
	return fmt.Sprintf("\n%s\n\n", renderBold(str))
}

func getFormattedProperties(properties []FindingProperty) string {
	formattedProperties := ""
	labelLength := 0

	for _, property := range properties {
		if len(property.Label) > labelLength {
			labelLength = len(property.Label) + 1
		}
	}

	labelAndPropertyFormat := "   %-" + fmt.Sprintf("%d", labelLength) + "s %s\n"

	for _, property := range properties {
		if property.Label == "" {
			formattedProperties += "\n"
			continue
		}
		formattedProperties += fmt.Sprintf(labelAndPropertyFormat, property.Label+":", property.Value)
	}

	return formattedProperties
}

func RenderTip(str string) string {
	return fmt.Sprintf("\n💡 Tip\n\n%s", str)
}

func reverseSlice(original []string) []string {
	// Create a copy of the slice using slice with no arguments
	reversed := original[:len(original)] // Shallow copy

	// Reverse the copied slice
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}

	return reversed
}

func RenderSummary(summary *json_schemas.TestSummary, orgName string, testPath string) (string, error) {
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

	reversedSlice := reverseSlice(summary.SeverityOrderAsc)

	for _, severity := range reversedSlice {
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
		Org:                             orgName,
		TestPath:                        testPath,
		Type:                            testType,
		TotalIssueCount:                 totalIssueCount,
		IgnoreIssueCount:                ignoredIssueCount,
		OpenIssueCountWithSeverities:    openIssueCountWithSeverities,
		IgnoredIssueCountWithSeverities: ignoredIssueCountWithSeverities,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generete test summary from template: %w", err)
	}

	return boxStyle.Render(buff.String()), nil
}
