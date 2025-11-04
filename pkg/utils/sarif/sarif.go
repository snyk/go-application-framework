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

		// Get metadata
		metadata := issue.GetMetadata()
		if metadata == nil {
			continue
		}

		// Get issue ID (for SCA, this is the vulnerability ID)
		issueID := issue.GetID()
		if issueID == "" {
			continue
		}

		if _, ok := sarifRules[issueID]; !ok {
			// Build shortDescription
			severity := issue.GetSeverity()
			componentName := ""
			if metadata.Component != nil {
				componentName = metadata.Component.Name
			}
			shortDesc := fmt.Sprintf("%s severity - %s vulnerability in %s",
				cases.Title(language.English).String(severity),
				issue.GetTitle(),
				componentName)

			// Build fullDescription with CVE IDs
			componentVersion := ""
			if metadata.Component != nil {
				componentVersion = metadata.Component.Version
			}
			fullDesc := fmt.Sprintf("%s@%s", componentName, componentVersion)
			cveIds := issue.GetCVEs()
			if len(cveIds) > 0 {
				fullDesc = fmt.Sprintf("(%s) %s", strings.Join(cveIds, ", "), fullDesc)
			}

			// Build help markdown using generic metadata
			helpMarkdown := buildHelpMarkdownGeneric(metadata, issue.GetDescription())

			// Build properties with tags including CWEs
			tags := []interface{}{"security"}
			for _, cwe := range issue.GetCWEs() {
				tags = append(tags, cwe)
			}
			// Add technology/ecosystem if available
			if metadata.Technology != "" {
				tags = append(tags, metadata.Technology)
			}

			cvssScore := metadata.CVSSScore
			properties := map[string]interface{}{
				"cvssv3_baseScore":  cvssScore,
				"security-severity": fmt.Sprintf("%.1f", cvssScore),
				"tags":              tags,
			}

			sarifRules[issueID] = map[string]interface{}{
				"id":               issueID,
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

		// Get metadata
		metadata := issue.GetMetadata()
		if metadata == nil {
			continue
		}

		// Get issue ID (for SCA, this is the vulnerability ID)
		issueID := issue.GetID()
		if issueID == "" {
			continue
		}

		// Create one result per issue (vulnerability) for backward compatibility
		// Use the first finding for location information
		firstFinding := findings[0]

		// Build message
		severity := issue.GetSeverity()
		componentName := ""
		if metadata.Component != nil {
			componentName = metadata.Component.Name
		}
		message := map[string]interface{}{
			"text": fmt.Sprintf("This file introduces a vulnerable %s package with a %s severity vulnerability.",
				componentName,
				severity),
		}

		// Build location using metadata
		location := buildScaLocation(firstFinding, metadata)

		// Build result
		sarifLevel := SeverityToSarifLevel(severity)
		sarifResult := map[string]interface{}{
			"ruleId":    issueID,
			"level":     sarifLevel,
			"message":   message,
			"locations": []interface{}{location},
		}

		// Add fixes if available
		if metadata.IsFixable && len(metadata.FixedInVersions) > 0 {
			fixes := buildScaFixes(firstFinding, metadata)
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

// buildHelpMarkdownGeneric constructs the help markdown section for SARIF rules using generic metadata
func buildHelpMarkdownGeneric(metadata *testapi.IssueMetadata, description string) string {
	var sb strings.Builder

	// Package Manager (Technology/Ecosystem)
	if metadata.Technology != "" {
		sb.WriteString(fmt.Sprintf("* Package Manager: %s\n", metadata.Technology))
	}

	// Vulnerable module (Component)
	if metadata.Component != nil {
		sb.WriteString(fmt.Sprintf("* Vulnerable module: %s\n", metadata.Component.Name))
	}

	// Introduced through
	if len(metadata.DependencyPaths) > 0 {
		// Get the root package from first path
		firstPath := metadata.DependencyPaths[0]
		parts := strings.Split(firstPath, " › ")
		if len(parts) > 1 {
			sb.WriteString(fmt.Sprintf("* Introduced through: %s, %s and others\n", parts[0], parts[1]))
		} else if len(parts) == 1 {
			sb.WriteString(fmt.Sprintf("* Introduced through: %s\n", parts[0]))
		}

		// Detailed paths
		sb.WriteString("### Detailed paths\n")
		for _, path := range metadata.DependencyPaths {
			sb.WriteString(fmt.Sprintf("* _Introduced through_: %s\n", path))
		}
	} else if metadata.Component != nil {
		// Fallback if no dependency paths available
		sb.WriteString(fmt.Sprintf("* Introduced through: %s@%s\n", metadata.Component.Name, metadata.Component.Version))
	}

	// Description
	if description != "" {
		sb.WriteString(description)
	}

	return sb.String()
}

func buildScaLocation(finding testapi.FindingData, metadata *testapi.IssueMetadata) map[string]interface{} {
	// Default to line 1 for manifest files
	uri := "package.json" // Default, should be determined from locations
	startLine := 1
	packageName := ""
	packageVersion := ""

	// Get package info from metadata
	if metadata.Component != nil {
		packageName = metadata.Component.Name
		packageVersion = metadata.Component.Version
	}

	// Try to extract actual file path and package version from locations
	if len(finding.Attributes.Locations) > 0 {
		loc := finding.Attributes.Locations[0]

		// Try source location first
		sourceLoc, err := loc.AsSourceLocation()
		if err == nil && sourceLoc.FilePath != "" {
			uri = sourceLoc.FilePath
			startLine = sourceLoc.FromLine
		}

		// Extract package info from PackageLocation if available
		pkgLoc, err := loc.AsPackageLocation()
		if err == nil {
			if pkgLoc.Package.Name != "" {
				packageName = pkgLoc.Package.Name
			}
			if pkgLoc.Package.Version != "" {
				packageVersion = pkgLoc.Package.Version
			}
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
				"fullyQualifiedName": fmt.Sprintf("%s@%s", packageName, packageVersion),
			},
		},
	}
}

func buildScaFixes(finding testapi.FindingData, metadata *testapi.IssueMetadata) []interface{} {
	if len(metadata.FixedInVersions) == 0 {
		return nil
	}

	fixedVersion := metadata.FixedInVersions[0]
	packageName := ""
	if metadata.Component != nil {
		packageName = metadata.Component.Name
	}

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
				"text": fmt.Sprintf("Upgrade to %s@%s", packageName, fixedVersion),
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
