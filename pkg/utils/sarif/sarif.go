package sarif

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/snyk/code-client-go/sarif"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
)

const (
	summaryType = "sast"
)

// Convert Sarif Level to internal Severity
func SarifLevelToSeverity(level string) string {
	var severity string
	if level == "note" {
		severity = "low"
	} else if level == "warning" {
		severity = "medium"
	} else if level == "error" {
		severity = "high"
	} else {
		severity = "unmapped"
	}

	return severity
}

func SeverityToSarifLevel(severity string) string {
	var level string
	if severity == "low" {
		level = "note"
	} else if severity == "medium" {
		level = "warning"
	} else if severity == "high" || severity == "critical" {
		level = "error"
	} else {
		level = "unmapped"
	}
	return level
}

// CreateCodeSummary Iterates through the sarif data and create a summary out of it.
func CreateCodeSummary(input *sarif.SarifDocument, projectPath string) *json_schemas.TestSummary {
	if input == nil {
		return nil
	}

	summary := json_schemas.NewTestSummary(summaryType, projectPath)
	resultMap := map[string]*json_schemas.TestSummaryResult{}

	summary.SeverityOrderAsc = []string{"low", "medium", "high"}

	for _, run := range input.Runs {
		for _, result := range run.Results {
			severity := SarifLevelToSeverity(result.Level)

			if _, ok := resultMap[severity]; !ok {
				resultMap[severity] = &json_schemas.TestSummaryResult{}
			}

			resultMap[severity].Total++

			// evaluate if the result is suppressed/ignored or not
			if IsHighestSuppressionStatus(result.Suppressions, sarif.Accepted) {
				resultMap[severity].Ignored++
			} else {
				resultMap[severity].Open++
			}
		}

		for _, coverage := range run.Properties.Coverage {
			if coverage.IsSupported {
				summary.Artifacts += coverage.Files
			}
		}
	}

	// fill final map
	for k, v := range resultMap {
		local := *v
		local.Severity = k
		summary.Results = append(summary.Results, local)
	}

	return summary
}

// IsHighestSuppressionStatus returns true if the suppression with the provided status exists and has the highest precedence.
func IsHighestSuppressionStatus(suppressions []sarif.Suppression, status sarif.SuppresionStatus) bool {
	suppression, suppressionStatus := GetHighestSuppression(suppressions)
	if suppression == nil {
		return false
	}

	return suppressionStatus == status
}

// GetHighestSuppression returns the suppression details if any and its status.
// It prioritizes suppressions based on their status: Accepted > UnderReview > Rejected.
// If multiple suppressions exist, the one with the highest precedence is returned.
// An empty Status is treated as Accepted.
// If no suppressions are found, returns nil.
func GetHighestSuppression(suppressions []sarif.Suppression) (*sarif.Suppression, sarif.SuppresionStatus) {
	for _, suppression := range suppressions {
		if suppression.Status == sarif.Accepted || suppression.Status == "" {
			return &suppression, sarif.Accepted
		}
	}

	for _, suppression := range suppressions {
		if suppression.Status == sarif.UnderReview {
			return &suppression, sarif.UnderReview
		}
	}

	for _, suppression := range suppressions {
		if suppression.Status == sarif.Rejected {
			return &suppression, sarif.Rejected
		}
	}
	return nil, ""
}

func ConvertTypeToDriverName(s string) string {
	switch s {
	case "sast":
		return "SnykCode"
	case "container":
		return "Snyk Container"
	case "iac":
		return "Snyk IaC"
	default:
		return "Snyk Open Source"
	}
}

// GetRulesFromTestResult extracts SARIF rules from test results for a specific finding type.
// Based on the TypeScript implementation in open-source-sarif-output.ts
func GetRulesFromTestResult(result testapi.TestResult, t testapi.FindingType) []map[string]interface{} {
	sarifRules := map[string]map[string]interface{}{}

	findings, _, err := result.Findings(context.Background())
	if err != nil {
		return []map[string]interface{}{}
	}

	for _, finding := range findings {
		if finding.Attributes.FindingType == t {
			for _, problem := range finding.Attributes.Problems {
				if discriminator, err := problem.Discriminator(); err == nil && discriminator != "snyk_vuln" {
					continue
				}

				vulnProblem, err := problem.AsSnykVulnProblem()
				if err != nil {
					continue
				}

				if _, ok := sarifRules[vulnProblem.Id]; !ok {
					// Build shortDescription: "${upperFirst(severity)} severity - ${title} vulnerability in ${packageName}"
					shortDesc := fmt.Sprintf("%s severity - %s vulnerability in %s",
						cases.Title(language.English).String(string(vulnProblem.Severity)),
						finding.Attributes.Title,
						vulnProblem.PackageName)

					// Build fullDescription: cves ? "(${cves}) ${name}@${version}" : "${name}@${version}"
					fullDesc := fmt.Sprintf("%s@%s", vulnProblem.PackageName, vulnProblem.PackageVersion)
					// TODO: Add CVE identifiers when available from References

					// Build help markdown (simplified version - can be enhanced)
					helpMarkdown := fmt.Sprintf("* Vulnerable module: %s\n* Introduced through: %s@%s\n\n%s",
						vulnProblem.PackageName,
						vulnProblem.PackageName,
						vulnProblem.PackageVersion,
						finding.Attributes.Description)

					// Build properties
					properties := map[string]interface{}{
						"cvssv3_baseScore":  vulnProblem.CvssBaseScore,                      // AWS
						"security-severity": fmt.Sprintf("%.1f", vulnProblem.CvssBaseScore), // GitHub
						"tags":              []string{"security"},                           // Can add CWEs and package manager
					}

					sarifRules[vulnProblem.Id] = map[string]interface{}{
						"id":               vulnProblem.Id,
						"shortDescription": shortDesc,
						"fullDescription":  fullDesc,
						"help_text":        "",
						"help_markdown":    helpMarkdown,
						"properties":       properties,
					}
				}
			}
		}
	}
	return slices.Collect(maps.Values(sarifRules))
}

// GetResultsFromTestResult extracts SARIF results from test results for a specific finding type.
// Currently supports SCA findings, can be extended for SAST later.
func GetResultsFromTestResult(result testapi.TestResult, t testapi.FindingType) []map[string]interface{} {
	var results []map[string]interface{}

	findings, _, err := result.Findings(context.Background())
	if err != nil {
		return results
	}

	for _, finding := range findings {
		if finding.Attributes.FindingType != t {
			continue
		}

		// Handle SCA findings
		if t == testapi.FindingTypeSca {
			for _, problem := range finding.Attributes.Problems {
				if discriminator, err := problem.Discriminator(); err == nil && discriminator != "snyk_vuln" {
					continue
				}

				vulnProblem, err := problem.AsSnykVulnProblem()
				if err != nil {
					continue
				}

				// Build message
				message := map[string]interface{}{
					"text": fmt.Sprintf("This file introduces a vulnerable %s package with a %s severity vulnerability.",
						vulnProblem.PackageName,
						vulnProblem.Severity),
				}

				// Build location - use first location if available, otherwise default
				location := buildScaLocation(finding, vulnProblem)

				// Build result
				sarifResult := map[string]interface{}{
					"ruleId":    vulnProblem.Id,
					"level":     SeverityToSarifLevel(string(vulnProblem.Severity)),
					"message":   message,
					"locations": []interface{}{location},
				}

				// Add fixes if available
				if vulnProblem.IsFixable && len(vulnProblem.InitiallyFixedInVersions) > 0 {
					fixes := buildScaFixes(finding, vulnProblem)
					if fixes != nil {
						sarifResult["fixes"] = fixes
					}
				}

				results = append(results, sarifResult)
			}
		}
		// TODO: Add SAST handling here later
		// else if t == testapi.FindingTypeSast { ... }
	}

	return results
}

func buildScaLocation(finding testapi.FindingData, vulnProblem testapi.SnykVulnProblem) map[string]interface{} {
	// Default to line 1 for manifest files
	uri := "package.json" // Default, should be determined from locations
	startLine := 1

	// Try to extract actual file path from locations
	if len(finding.Attributes.Locations) > 0 {
		loc := finding.Attributes.Locations[0]
		sourceLoc, err := loc.AsSourceLocation()
		if err == nil && sourceLoc.FilePath != "" {
			uri = sourceLoc.FilePath
			startLine = sourceLoc.FromLine
		}
	}

	return map[string]interface{}{
		"physicalLocation": map[string]interface{}{
			"artifactLocation": map[string]interface{}{
				"uri": uri,
			},
			"region": map[string]interface{}{
				"startLine": startLine,
			},
		},
		"logicalLocations": []interface{}{
			map[string]interface{}{
				"fullyQualifiedName": fmt.Sprintf("%s@%s", vulnProblem.PackageName, vulnProblem.PackageVersion),
			},
		},
	}
}

func buildScaFixes(finding testapi.FindingData, vulnProblem testapi.SnykVulnProblem) []interface{} {
	if len(vulnProblem.InitiallyFixedInVersions) == 0 {
		return nil
	}

	fixedVersion := vulnProblem.InitiallyFixedInVersions[0]
	uri := "package.json"
	startLine := 1

	// Try to extract actual file path from locations
	if len(finding.Attributes.Locations) > 0 {
		loc := finding.Attributes.Locations[0]
		sourceLoc, err := loc.AsSourceLocation()
		if err == nil && sourceLoc.FilePath != "" {
			uri = sourceLoc.FilePath
			startLine = sourceLoc.FromLine
		}
	}

	return []interface{}{
		map[string]interface{}{
			"description": map[string]interface{}{
				"text": fmt.Sprintf("Upgrade to %s", fixedVersion),
			},
			"artifactChanges": []interface{}{
				map[string]interface{}{
					"artifactLocation": map[string]interface{}{
						"uri": uri,
					},
					"replacements": []interface{}{
						map[string]interface{}{
							"deletedRegion": map[string]interface{}{
								"startLine": startLine,
							},
							"insertedContent": map[string]interface{}{
								"text": fixedVersion,
							},
						},
					},
				},
			},
		},
	}
}
