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
	ID         string
	Severity   string
	Title      string
	Ignored    bool
	Properties []FindingProperty
}

type FindingProperty struct {
	Label string
	Value string
}

type Presenter struct {
	ShowIgnored bool
	ShowOpen    bool
	Input       sarif.SarifDocument
	OrgName     string
	TestPath    string
}

type PresenterOption func(*Presenter)

func WithIgnored(showIgnored bool) PresenterOption {
	return func(p *Presenter) {
		p.ShowIgnored = showIgnored
	}
}

func WithOpen(showOpen bool) PresenterOption {
	return func(p *Presenter) {
		p.ShowOpen = showOpen
	}
}

func WithOrgName(orgName string) PresenterOption {
	return func(p *Presenter) {
		p.OrgName = orgName
	}
}

func WithTestPath(testPath string) PresenterOption {
	return func(p *Presenter) {
		p.TestPath = testPath
	}
}

func SarifTestResults(sarifDocument sarif.SarifDocument, options ...PresenterOption) *Presenter {
	p := &Presenter{
		ShowIgnored: false,
		ShowOpen:    true,
		Input:       sarifDocument,
		OrgName:     "",
		TestPath:    "",
	}

	for _, option := range options {
		option(p)
	}

	return p
}

func (p *Presenter) Render() (string, error) {
	findings := convertSarifToFindingsList(p.Input)
	summary := sarif_utils.CreateCodeSummary(&p.Input)

	str := strings.Join([]string{
		"",
		renderBold(fmt.Sprintf("Testing %s ...", p.TestPath)),
		RenderFindings(SortFindings(findings, summary.SeverityOrderAsc), p.ShowIgnored, p.ShowOpen),
		RenderSummary(summary, p.OrgName, p.TestPath),
		getFinalTip(p.ShowIgnored, p.ShowOpen),
		"",
	}, "\n")

	return str, nil
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

			var findingProperties []FindingProperty

			findingProperties = append(findingProperties, FindingProperty{
				Label: "Path",
				Value: fmt.Sprintf("%s, line %d",
					location.PhysicalLocation.ArtifactLocation.URI,
					location.PhysicalLocation.Region.StartLine,
				),
			})

			findingProperties = append(findingProperties, FindingProperty{
				Label: "Info",
				Value: result.Message.Text,
			})

			findingProperties = append(findingProperties, FindingProperty{
				Label: "",
				Value: "",
			})

			for _, suppression := range result.Suppressions {
				expiration := ""
				if suppression.Properties.Expiration != nil {
					expiration = *suppression.Properties.Expiration
				}

				findingProperties = append(findingProperties, FindingProperty{
					Label: "Expiration",
					Value: expiration,
				})

				findingProperties = append(findingProperties, FindingProperty{
					Label: "Category",
					Value: strings.Replace(string(suppression.Properties.Category), "wont-fix", "Won't fix", 1),
				})

				// TODO: Verify date formatting
				s, err := time.Parse(time.RFC3339, suppression.Properties.IgnoredOn)

				if err == nil {
					findingProperties = append(findingProperties, FindingProperty{
						Label: "Ignored on",
						Value: s.Format("January 02, 2006"),
					})
				}

				findingProperties = append(findingProperties, FindingProperty{
					Label: "Ignored by",
					Value: suppression.Properties.IgnoredBy.Name,
				})

				findingProperties = append(findingProperties, FindingProperty{
					Label: "Reason",
					Value: suppression.Justification,
				})
			}

			findings = append(findings, Finding{
				ID:         result.RuleID,
				Severity:   severity,
				Title:      title,
				Ignored:    isIgnored,
				Properties: findingProperties,
			})
		}
	}
	return findings
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
