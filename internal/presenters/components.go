package presenters

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
)

const valueStyleWidth = 80

func errorLevelToStyle(errLevel string) lipgloss.Style {
	style := lipgloss.NewStyle().
		PaddingLeft(1).
		PaddingRight(1).
		Background(lipgloss.Color("1")).
		Foreground(lipgloss.Color("15"))

	if errLevel == "warn" {
		style.
			Background(lipgloss.Color("3")).
			Foreground(lipgloss.Color("0"))
	}

	return style
}

func RenderError(err snyk_errors.Error) string {
	var body []string

	level := strings.ToUpper(err.Level)
	backgroundHighlight := errorLevelToStyle(err.Level)
	label := lipgloss.NewStyle().Width(8)
	value := lipgloss.NewStyle().PaddingLeft(1).PaddingRight(1)

	if len(err.Detail) > 0 {
		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render("Info:"),
			value.Copy().Width(valueStyleWidth).Render(err.Detail),
		))
	}

	if err.StatusCode > 0 {
		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render("Status:"),
			value.Render(strconv.Itoa(err.StatusCode)+" "+http.StatusText(err.StatusCode)),
		))
	}

	if len(err.Description) > 0 {
		desc := err.Description
		re := regexp.MustCompile("\n+")
		lines := re.Split(desc, -1)

		if len(lines) > 1 {
			lines = lines[0:2]
			for i, l := range lines {
				lines[i] = strings.Trim(l, " \n")
			}
			desc = strings.Join(lines, " ")
		}

		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render("Details:"),
			value.Copy().Width(valueStyleWidth).Render(desc),
		))
	}

	title := strings.TrimSpace(err.Title)
	if len(err.ErrorCode) > 0 {
		fragment := "#" + strings.ToLower(err.ErrorCode)
		link := constants.SNYK_DOCS_URL + constants.SNYK_DOCS_ERROR_CATALOG_PATH + fragment
		err.Links = append([]string{link}, err.Links...)
		title = title + fmt.Sprintf(" (%s)", err.ErrorCode)
	}

	if len(err.Links) > 0 {
		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render("Docs:"),
			value.Render(strings.Join(err.Links, "\n")),
		))
	}

	title = renderBold(title)

	return "\n" + backgroundHighlight.MarginRight(6-len(level)).Render(level) + " " + title + "\n" +
		strings.Join(body, "\n")
}

func RenderFindings(findings []Finding, showIgnored bool, isSeverityThresholdApplied bool) string {
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

	if isSeverityThresholdApplied {
		response += RenderTip("You are currently viewing results with --severity-threshold applied.\nTo view all issues, remove the --severity-threshold flag\n")
	}

	if showIgnored {
		response += RenderDivider()
		response += RenderTitle("Ignored Issues")

		ignoredFindings := ""

		for _, finding := range findings {
			if !finding.Ignored {
				continue
			}
			ignoredFindings += RenderFinding(finding)
		}

		if ignoredFindings == "" {
			response += renderBold("  There are no ignored issues\n")
		} else {
			response += ignoredFindings
		}

		response += RenderTip("Ignores are currently managed in the Snyk Web UI.\nTo edit or remove the ignore please go to: "+RenderLink("https://app.snyk.io/")) + "\n"
	}

	return response
}

func RenderFinding(finding Finding) string {
	titlePrefix := " ✗ "
	ignorePrefix := ""

	if finding.Ignored {
		titlePrefix = ""
		ignorePrefix = " ! [ IGNORED ] "
	}

	properties := getFormattedProperties(finding.Properties)

	return strings.Join([]string{
		fmt.Sprintf("%s%s %s",
			ignorePrefix,
			renderInSeverityColor(finding.Severity, fmt.Sprintf("%s[%s]", titlePrefix, strings.ToUpper(finding.Severity))),
			renderBold(finding.Title),
		),
		properties,
	}, "\n")
}

func RenderLink(str string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("12")).
		Render(str)
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
	body := lipgloss.NewStyle().
		PaddingLeft(3)
	return fmt.Sprintf("\n💡 Tip\n\n%s", body.Render(str))
}

func FilterSeverityASC(original []string, severityMinLevel string) []string {
	if severityMinLevel == "" {
		return original
	}

	minLevelPointer := slices.Index(original, severityMinLevel)

	if minLevelPointer >= 0 {
		return original[minLevelPointer:]
	}

	return original
}

type SummaryData struct {
	SummaryTitle                    string
	Org                             string
	TestPath                        string
	Type                            string
	TotalIssueCount                 int
	IgnoreIssueCount                int
	OpenIssueCountWithSeverities    string
	IgnoredIssueCountWithSeverities string
}

func PrepareSummary(summary *json_schemas.TestSummary, orgName string, testPath string, severityMinLevel string) (data SummaryData) {
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
					continue
				}
				totalIssueCount += result.Total
				openIssueCount += result.Open
				ignoredIssueCount += result.Ignored
				openIssueLabelledCount += severityCount(severity, result.Open)
				ignoredIssueLabelledCount += severityCount(severity, result.Ignored)
			}
		}

		if !strings.Contains(openIssueLabelledCount, strings.ToUpper(severity)) && severityMinLevel == "" {
			openIssueLabelledCount += severityCount(severity, 0)
		}

		if !strings.Contains(ignoredIssueLabelledCount, strings.ToUpper(severity)) && severityMinLevel == "" {
			ignoredIssueLabelledCount += severityCount(severity, 0)
		}
	}

	openIssueCountWithSeverities := fmt.Sprintf("%s [%s]", renderBold(strconv.Itoa(openIssueCount)), openIssueLabelledCount)
	ignoredIssueCountWithSeverities := fmt.Sprintf("%s [%s]", renderBold(strconv.Itoa(ignoredIssueCount)), ignoredIssueLabelledCount)
	testType := summary.Type
	if testType == "sast" {
		testType = "Static code analysis"
	}

	data.SummaryTitle = renderBold("Test Summary")
	data.Org = orgName
	data.TestPath = testPath
	data.Type = testType
	data.TotalIssueCount = totalIssueCount
	data.IgnoreIssueCount = ignoredIssueCount
	data.OpenIssueCountWithSeverities = openIssueCountWithSeverities
	data.IgnoredIssueCountWithSeverities = ignoredIssueCountWithSeverities
	return data
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

	summaryData := PrepareSummary(summary, orgName, testPath, severityMinLevel)
	err := summaryTemplate.Execute(&buff, summaryData)
	if err != nil {
		return "", fmt.Errorf("failed to generete test summary from template: %w", err)
	}

	return boxStyle.Render(buff.String()), nil
}

func severityCount(severity string, count int) string {
	return renderInSeverityColor(severity, fmt.Sprintf(" %d %s ", count, strings.ToUpper(severity)))
}
