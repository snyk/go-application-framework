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

func RenderFindings(findings []Finding, showIgnored bool) string {
	if len(findings) == 0 {
		return ""
	}

	response := ""

	response += RenderTitle("Open Issues")

	for _, finding := range findings {
		if finding.Ignored {
			continue
		}
		response += RenderFinding(finding)
	}

	if showIgnored {
		response += RenderDivider()
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
	return fmt.Sprintf("\n💡 Tip\n\n   %s", str)
}

func FilterSeverityASC(original []string, severityMinLevel string) []string {
	minLevelPointer := slices.Index(original, severityMinLevel)
	if minLevelPointer >= 0 {
		return original[minLevelPointer:]
	}
	return original
}

func RenderSummary(summary *json_schemas.TestSummary, orgName string, testPath string, severityMinLevel string) (string, error) {
	var buff bytes.Buffer
	var summaryTemplate = template.Must(template.New("summary").Parse(`{{ .SummaryTitle }}

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

	filteredSeverityASC := FilterSeverityASC(summary.SeverityOrderAsc, severityMinLevel)
	reversedSlice := slices.Clone(summary.SeverityOrderAsc)
	slices.Reverse(reversedSlice)

	for _, severity := range reversedSlice {
		satisfyMinLevel := slices.Contains(filteredSeverityASC, severity)
		for _, result := range summary.Results {
			if result.Severity == severity {
				if !satisfyMinLevel {
					openIssueLabelledCount += renderInSeverityColor(severity, fmt.Sprintf(" %d %s ", 0, strings.ToUpper(severity)))
					ignoredIssueLabelledCount += renderInSeverityColor(severity, fmt.Sprintf(" %d %s ", 0, strings.ToUpper(severity)))
					continue
				}
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
		SummaryTitle                    string
		Org                             string
		TestPath                        string
		Type                            string
		TotalIssueCount                 int
		IgnoreIssueCount                int
		OpenIssueCountWithSeverities    string
		IgnoredIssueCountWithSeverities string
	}{
		SummaryTitle:                    renderBold("Test Summary"),
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
