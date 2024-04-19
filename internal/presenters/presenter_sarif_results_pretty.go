package presenters

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/snyk/code-client-go/sarif"
	sarif_utils "github.com/snyk/go-application-framework/internal/utils/sarif"
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
		RenderFindings(SortFindings(findings, summary.SeverityOrderAsc), showIgnored, showOpen),
		RenderSummary(summary, meta),
		getFinalTip(showIgnored, showOpen),
		"",
	}, "\n")

	return str, nil
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

	return RenderTip(tip)
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
