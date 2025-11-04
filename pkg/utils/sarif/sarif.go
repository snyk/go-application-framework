package sarif

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

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

// GetRulesFromIssues extracts SARIF rules from a list of Issues for a specific finding type.
// Based on the TypeScript implementation in open-source-sarif-output.ts
func GetRulesFromIssues(issuesList []testapi.Issue, t testapi.FindingType) []map[string]interface{} {
	sarifRules := map[string]map[string]interface{}{}

	for _, issue := range issuesList {
		// Only process issues of the specified finding type
		if issue.GetFindingType() != t {
			continue
		}

		findings := issue.GetFindings()
		if len(findings) == 0 {
			continue
		}

		// Get SnykVulnProblem from issue
		vulnProblem, err := issue.GetSnykVulnProblem()
		if err != nil {
			// For backward compatibility, try to extract from first finding directly
			firstFinding := findings[0]
			if firstFinding.Attributes != nil {
				for _, problem := range firstFinding.Attributes.Problems {
					discriminator, err := problem.Discriminator()
					if err != nil {
						continue
					}
					if discriminator == "snyk_vuln" {
						if vp, err := problem.AsSnykVulnProblem(); err == nil {
							vulnProblem = &vp
							break
						}
					}
				}
			}
			// If still no vuln problem found, skip this issue
			if vulnProblem == nil {
				continue
			}
		}

		if _, ok := sarifRules[vulnProblem.Id]; !ok {
			// Build shortDescription
			severity := issue.GetSeverity()
			if severity == "" {
				severity = string(vulnProblem.Severity)
			}
			shortDesc := fmt.Sprintf("%s severity - %s vulnerability in %s",
				cases.Title(language.English).String(severity),
				issue.GetTitle(),
				issue.GetPackageName())

			// Build fullDescription with CVE IDs
			fullDesc := fmt.Sprintf("%s@%s", issue.GetPackageName(), issue.GetPackageVersion())
			cveIds := issue.GetCVEs()
			if len(cveIds) > 0 {
				fullDesc = fmt.Sprintf("(%s) %s", strings.Join(cveIds, ", "), fullDesc)
			}

			// Build dependency paths
			depPaths := issue.GetDependencyPaths()

			// Build help markdown with package manager, vulnerable module, and detailed paths
			helpMarkdown := buildHelpMarkdown(*vulnProblem, depPaths, issue.GetDescription())

			// Build properties with tags including CWEs
			tags := []interface{}{"security"}
			for _, cwe := range issue.GetCWEs() {
				tags = append(tags, cwe)
			}
			// Add ecosystem if available - try issue first, then vulnProblem as fallback
			ecosystemName := issue.GetEcosystem()
			if ecosystemName == "" {
				// Extract from vulnProblem.Ecosystem as fallback
				if buildEco, err := vulnProblem.Ecosystem.AsSnykvulndbBuildPackageEcosystem(); err == nil {
					ecosystemName = buildEco.PackageManager
				} else if osEco, err := vulnProblem.Ecosystem.AsSnykvulndbOsPackageEcosystem(); err == nil {
					ecosystemName = osEco.OsName
				}
			}
			if ecosystemName != "" {
				tags = append(tags, ecosystemName)
			}

			cvssScore := issue.GetCvssScore()
			if cvssScore == 0.0 {
				cvssScore = float32(vulnProblem.CvssBaseScore)
			}
			properties := map[string]interface{}{
				"cvssv3_baseScore":  cvssScore,
				"security-severity": fmt.Sprintf("%.1f", cvssScore),
				"tags":              tags,
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

	// Convert map values to slice and sort by rule ID for deterministic output
	rules := slices.Collect(maps.Values(sarifRules))
	sort.Slice(rules, func(i, j int) bool {
		idI, okI := rules[i]["id"].(string)
		idJ, okJ := rules[j]["id"].(string)
		if !okI || !okJ {
			return false
		}
		return idI < idJ
	})

	return rules
}

// GetRulesFromTestResult extracts SARIF rules from test results for a specific finding type.
// This function maintains backward compatibility by wrapping GetRulesFromIssues.
// Based on the TypeScript implementation in open-source-sarif-output.ts
func GetRulesFromTestResult(result testapi.TestResult, t testapi.FindingType) []map[string]interface{} {
	ctx := context.Background()
	issuesList, err := testapi.NewIssuesFromTestResult(ctx, result)
	if err != nil {
		return []map[string]interface{}{}
	}
	return GetRulesFromIssues(issuesList, t)
}

// GetResultsFromIssues extracts SARIF results from a list of Issues for a specific finding type.
func GetResultsFromIssues(issuesList []testapi.Issue, t testapi.FindingType) []map[string]interface{} {
	// Handle SCA findings
	if t == testapi.FindingTypeSca {
		return getScaResultsFromIssues(issuesList)
	}
	// TODO: Add SAST handling here later
	// else if t == testapi.FindingTypeSast { return getSastResultsFromIssues(issuesList) }

	return []map[string]interface{}{}
}

// GetResultsFromTestResult extracts SARIF results from test results for a specific finding type.
// This function maintains backward compatibility by wrapping GetResultsFromIssues.
func GetResultsFromTestResult(result testapi.TestResult, t testapi.FindingType) []map[string]interface{} {
	ctx := context.Background()
	issuesList, err := testapi.NewIssuesFromTestResult(ctx, result)
	if err != nil {
		return []map[string]interface{}{}
	}
	return GetResultsFromIssues(issuesList, t)
}

// getScaResultsFromIssues creates SARIF results from a list of SCA Issues.
// For backward compatibility, creates one result per issue (vulnerability).
// Issues are already grouped by vulnerability ID, so this matches the original behavior.
func getScaResultsFromIssues(issuesList []testapi.Issue) []map[string]interface{} {
	var results []map[string]interface{}

	for _, issue := range issuesList {
		// Skip non-SCA issues
		if issue.GetFindingType() != testapi.FindingTypeSca {
			continue
		}

		findings := issue.GetFindings()
		if len(findings) == 0 {
			continue
		}

		// Get SnykVulnProblem from issue (for shared data like ID, severity, etc.)
		issueVulnProblem, err := issue.GetSnykVulnProblem()
		if err != nil {
			// For backward compatibility, try to extract from first finding directly
			firstFinding := findings[0]
			if firstFinding.Attributes != nil {
				for _, problem := range firstFinding.Attributes.Problems {
					discriminator, err := problem.Discriminator()
					if err != nil {
						continue
					}
					if discriminator == "snyk_vuln" {
						if vp, err := problem.AsSnykVulnProblem(); err == nil {
							issueVulnProblem = &vp
							break
						}
					}
				}
			}
			// If still no vuln problem found, skip this issue
			if issueVulnProblem == nil {
				continue
			}
		}

		// Create one result per issue (vulnerability) for backward compatibility
		// Use the first finding for location information
		firstFinding := findings[0]

		// Extract vulnProblem from first finding to get fixability info
		vulnProblem := issueVulnProblem
		if firstFinding.Attributes != nil {
			for _, problem := range firstFinding.Attributes.Problems {
				discriminator, err := problem.Discriminator()
				if err != nil {
					continue
				}
				if discriminator == "snyk_vuln" {
					if vp, err := problem.AsSnykVulnProblem(); err == nil {
						vulnProblem = &vp
						break
					}
				}
			}
		}

		// Build message
		severity := issue.GetSeverity()
		if severity == "" {
			severity = string(vulnProblem.Severity)
		}
		packageName := issue.GetPackageName()
		if packageName == "" {
			packageName = vulnProblem.PackageName
		}
		message := map[string]interface{}{
			"text": fmt.Sprintf("This file introduces a vulnerable %s package with a %s severity vulnerability.",
				packageName,
				severity),
		}

		// Build location
		location := buildScaLocation(firstFinding, *vulnProblem)

		// Build result
		sarifLevel := SeverityToSarifLevel(severity)
		sarifResult := map[string]interface{}{
			"ruleId":    vulnProblem.Id,
			"level":     sarifLevel,
			"message":   message,
			"locations": []interface{}{location},
		}

		// Add fixes if available - check from vulnProblem directly
		if vulnProblem.IsFixable && len(vulnProblem.InitiallyFixedInVersions) > 0 {
			fixes := buildScaFixes(firstFinding, *vulnProblem)
			if fixes != nil {
				sarifResult["fixes"] = fixes
			}
		}

		results = append(results, sarifResult)
	}

	// Sort results by ruleId for deterministic output
	sort.Slice(results, func(i, j int) bool {
		ruleIdI, okI := results[i]["ruleId"].(string)
		ruleIdJ, okJ := results[j]["ruleId"].(string)
		if !okI || !okJ {
			return false
		}
		return ruleIdI < ruleIdJ
	})

	return results
}

// buildHelpMarkdown constructs the help markdown section for SARIF rules
func buildHelpMarkdown(vulnProblem testapi.SnykVulnProblem, depPaths []string, description string) string {
	var sb strings.Builder

	// Package Manager - extract ecosystem name from vulnProblem
	var ecosystemName string
	if buildEco, err := vulnProblem.Ecosystem.AsSnykvulndbBuildPackageEcosystem(); err == nil {
		ecosystemName = buildEco.PackageManager
	} else if osEco, err := vulnProblem.Ecosystem.AsSnykvulndbOsPackageEcosystem(); err == nil {
		ecosystemName = osEco.OsName
	}
	sb.WriteString(fmt.Sprintf("* Package Manager: %s\n", ecosystemName))

	// Vulnerable module
	sb.WriteString(fmt.Sprintf("* Vulnerable module: %s\n", vulnProblem.PackageName))

	// Introduced through
	if len(depPaths) > 0 {
		// Get the root package from first path
		firstPath := depPaths[0]
		parts := strings.Split(firstPath, " › ")
		if len(parts) > 1 {
			sb.WriteString(fmt.Sprintf("* Introduced through: %s, %s and others\n", parts[0], parts[1]))
		} else if len(parts) == 1 {
			sb.WriteString(fmt.Sprintf("* Introduced through: %s\n", parts[0]))
		}

		// Detailed paths
		sb.WriteString("### Detailed paths\n")
		for _, path := range depPaths {
			sb.WriteString(fmt.Sprintf("* _Introduced through_: %s\n", path))
		}
	} else {
		sb.WriteString(fmt.Sprintf("* Introduced through: %s@%s\n", vulnProblem.PackageName, vulnProblem.PackageVersion))
	}

	// Description
	sb.WriteString(description)

	return sb.String()
}

func buildScaLocation(finding testapi.FindingData, vulnProblem testapi.SnykVulnProblem) map[string]interface{} {
	// Default to line 1 for manifest files
	uri := "package.json" // Default, should be determined from locations
	startLine := 1
	packageVersion := vulnProblem.PackageVersion

	// Try to extract actual file path and package version from locations
	if len(finding.Attributes.Locations) > 0 {
		loc := finding.Attributes.Locations[0]

		// Try source location first
		sourceLoc, err := loc.AsSourceLocation()
		if err == nil && sourceLoc.FilePath != "" {
			uri = sourceLoc.FilePath
			startLine = sourceLoc.FromLine
		}

		// Extract package version from PackageLocation if available
		pkgLoc, err := loc.AsPackageLocation()
		if err == nil && pkgLoc.Package.Version != "" {
			packageVersion = pkgLoc.Package.Version
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
				"fullyQualifiedName": fmt.Sprintf("%s@%s", vulnProblem.PackageName, packageVersion),
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
				"text": fmt.Sprintf("Upgrade to %s@%s", vulnProblem.PackageName, fixedVersion),
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
