package presenters

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/snyk/code-client-go/sarif"
	sarif_utils "github.com/snyk/go-application-framework/internal/utils/sarif"

	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
)

type Finding struct {
	ID               string
	Severity         string
	Title            string
	Message          string
	Path             string
	Line             int
	Ignored          bool
	IgnoreProperties []IgnoreProperty
}

type IgnoreProperty struct {
	Label string
	Value string
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
			var rule sarif.Rule
			for _, ruleItem := range run.Tool.Driver.Rules {
				if ruleItem.ID == result.RuleID {
					rule = ruleItem
					break
				}
			}

			severity := sarif_utils.SarifLevelToSeverity(result.Level)

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

			isIgnored := len(result.Suppressions) > 0

			var ignoreProperties []IgnoreProperty

			for _, suppression := range result.Suppressions {
				ignoreProperties = append(ignoreProperties, IgnoreProperty{
					Label: "Expiration",
					Value: fmt.Sprintf("%s", *suppression.Properties.Expiration),
				})

				ignoreProperties = append(ignoreProperties, IgnoreProperty{
					Label: "Category",
					Value: strings.Replace(string(suppression.Properties.Category), "wont-fix", "Won't fix", 1),
				})

				// TODO: Verify date formatting
				s, err := time.Parse(time.RFC3339, suppression.Properties.IgnoredOn)

				if err == nil {
					ignoreProperties = append(ignoreProperties, IgnoreProperty{
						Label: "Ignored on",
						Value: s.Format("January 02, 2006"),
					})
				} else {
					panic(err)
				}

				ignoreProperties = append(ignoreProperties, IgnoreProperty{
					Label: "Ignored by",
					Value: suppression.Properties.IgnoredBy.Name,
				})

				ignoreProperties = append(ignoreProperties, IgnoreProperty{
					Label: "Reason",
					Value: suppression.Justification,
				})
			}

			findings = append(findings, Finding{
				ID:               result.RuleID,
				Severity:         severity,
				Title:            title,
				Path:             location.PhysicalLocation.ArtifactLocation.URI,
				Line:             location.PhysicalLocation.Region.StartLine,
				Message:          result.Message.Text,
				Ignored:          isIgnored,
				IgnoreProperties: ignoreProperties,
			})
		}
	}
	return findings
}

type TestMeta struct {
	OrgName  string
	TestPath string
}

func PresenterSarifResultsPretty(input sarif.SarifDocument, meta TestMeta, showIgnored bool, showOpen bool) (string, error) {
	findings := convertSarifToFindingsList(input)
	summary := sarif_utils.CreateCodeSummary(&input)

	str := strings.Join([]string{
		"",
		renderBold(fmt.Sprintf("Testing %s ...", meta.TestPath)),
		renderFindings(SortFindings(findings, summary.SeverityOrderAsc), showIgnored, showOpen),
		renderSummary(summary, meta),
		getFinalTip(showIgnored, showOpen),
		"",
	}, "\n")

	return str, nil
}

func renderFindings(findings []Finding, showIgnored bool, showOpen bool) string {
	if len(findings) == 0 {
		return ""
	}

	response := ""

	if showOpen {
		response += renderTitle("Open Issues")

		for _, finding := range findings {
			if finding.Ignored {
				continue
			}
			response += renderFinding(finding)
		}
	}

	if showOpen && showIgnored {
		response += renderDivider()
	}

	if showIgnored {
		response += renderTitle("Ignored Issues")

		for _, finding := range findings {
			if !finding.Ignored {
				continue
			}
			response += renderFinding(finding)
		}

		response += renderTip("Ignores are currently managed in the Snyk Web UI.\nTo edit or remove the ignore please go to: https://app.snyk.io/") + "\n"
	}

	return response
}

func renderFinding(finding Finding) string {
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

func getIgnoredProperties(finding Finding, ignoredProperties string) string {
	labelLength := 0

	for _, property := range finding.IgnoreProperties {
		if len(property.Label) > labelLength {
			labelLength = len(property.Label) + 1
		}
	}

	labelAndPropertyFormat := "   %-" + fmt.Sprintf("%d", labelLength) + "s %s\n"

	for _, property := range finding.IgnoreProperties {
		ignoredProperties += fmt.Sprintf(labelAndPropertyFormat, property.Label+":", property.Value)
	}

	return ignoredProperties
}

func getFinalTip(showIgnored bool, showOpen bool) string {
	tip := "To view ignored issues, use the --include-ignores option. To view ignored issues only, use the --only-ignores option."
	if showIgnored {
		tip = `To view ignored issues only, use the --only-ignores option.`
	}

	if showIgnored && !showOpen {
		tip = `To view ignored and open issues, use the --include-ignores option.`
	}

	return renderTip(tip)
}

func renderDivider() string {
	return "─────────────────────────────────────────────────────\n"
}

func renderTitle(str string) string {
	return fmt.Sprintf("\n%s\n\n", renderBold(str))
}

func renderTip(str string) string {
	return fmt.Sprintf("\n💡 Tip\n\n%s", str)
}

func renderSummary(summary *json_schemas.TestSummary, meta TestMeta) string {
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

func SortFindings(findings []Finding, order []string) []Finding {
	result := make([]Finding, 0, len(findings))

	result = append(result, findings...)

	slices.SortFunc(result, func(a, b Finding) int {
		if a.Severity != b.Severity {
			return slices.Index(order, a.Severity) - slices.Index(order, b.Severity)
		}

		return 0
	})

	return result
}
