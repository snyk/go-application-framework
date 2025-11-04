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

		// Get issue ID (for SCA, this is the vulnerability ID)
		issueID := issue.GetID()
		if issueID == "" {
			continue
		}

		if _, ok := sarifRules[issueID]; !ok {
			// Build shortDescription
			severity := issue.GetSeverity()
			var componentName string
			if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentName); ok {
				componentName, _ = val.(string)
			}
			
			shortDesc := fmt.Sprintf("%s severity - %s vulnerability in %s",
				cases.Title(language.English).String(severity),
				issue.GetTitle(),
				componentName)

			// Build fullDescription with CVE IDs
			var componentVersion string
			if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentVersion); ok {
				componentVersion, _ = val.(string)
			}
			fullDesc := fmt.Sprintf("%s@%s", componentName, componentVersion)
			cveIds := issue.GetCVEs()
			if len(cveIds) > 0 {
				fullDesc = fmt.Sprintf("(%s) %s", strings.Join(cveIds, ", "), fullDesc)
			}

			// Build help markdown
			helpMarkdown := buildHelpMarkdownGeneric(issue, t)

			// Build properties with tags including CWEs
			tags := []interface{}{"security"}
			for _, cwe := range issue.GetCWEs() {
				tags = append(tags, cwe)
			}
			// Add technology/ecosystem if available
			var technology string
			if val, ok := issue.GetMetadata(testapi.MetadataKeyTechnology); ok {
				technology, _ = val.(string)
			}
			if technology != "" {
				tags = append(tags, technology)
			}

			var cvssScore float32
			if val, ok := issue.GetMetadata(testapi.MetadataKeyCVSSScore); ok {
				cvssScore, _ = val.(float32)
			}
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
	return getResultsFromIssues(issuesList, t)
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

// getResultsFromIssues creates SARIF results from a list of Issues for a specific finding type.
// For backward compatibility, creates one result per issue (vulnerability for SCA).
// Issues are already grouped by vulnerability ID or key, so this matches the original behavior.
func getResultsFromIssues(issuesList []testapi.Issue, findingType testapi.FindingType) []map[string]interface{} {
	var results []map[string]interface{}

	for _, issue := range issuesList {
		// Skip issues not matching the specified finding type
		if issue.GetFindingType() != findingType {
			continue
		}

		findings := issue.GetFindings()
		if len(findings) == 0 {
			continue
		}

		// Get issue ID (vulnerability ID for SCA, rule ID for SAST, etc.)
		issueID := issue.GetID()
		if issueID == "" {
			continue
		}

		// Create one result per issue for backward compatibility
		// Use the first finding for location information
		firstFinding := findings[0]

		// Build message
		severity := issue.GetSeverity()
		var componentName string
		if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentName); ok {
			componentName, _ = val.(string)
		}
		
		message := map[string]interface{}{
			"text": fmt.Sprintf("This file introduces a vulnerable %s package with a %s severity vulnerability.",
				componentName,
				severity),
		}

		// Build location
		location := buildLocation(firstFinding, issue)

		// Build result
		sarifLevel := SeverityToSarifLevel(severity)
		sarifResult := map[string]interface{}{
			"ruleId":    issueID,
			"level":     sarifLevel,
			"message":   message,
			"locations": []interface{}{location},
		}

		// Add fixes if available
		var isFixable bool
		if val, ok := issue.GetMetadata(testapi.MetadataKeyIsFixable); ok {
			isFixable, _ = val.(bool)
		}
		var fixedVersions []string
		if val, ok := issue.GetMetadata(testapi.MetadataKeyFixedInVersions); ok {
			fixedVersions, _ = val.([]string)
		}
		if isFixable && len(fixedVersions) > 0 {
			fixes := buildFixes(firstFinding, issue)
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

// buildHelpMarkdownGeneric constructs the help markdown section for SARIF rules
func buildHelpMarkdownGeneric(issue testapi.Issue, findingType testapi.FindingType) string {
	var sb strings.Builder

	// Technology/Ecosystem - use appropriate terminology based on finding type
	var technology string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyTechnology); ok {
		technology, _ = val.(string)
	}
	if technology != "" {
		if findingType == testapi.FindingTypeSca {
			sb.WriteString(fmt.Sprintf("* Package Manager: %s\n", technology))
		} else {
			sb.WriteString(fmt.Sprintf("* Technology: %s\n", technology))
		}
	}

	// Component - use appropriate terminology based on finding type
	var componentName string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentName); ok {
		componentName, _ = val.(string)
	}
	if componentName != "" {
		if findingType == testapi.FindingTypeSca {
			sb.WriteString(fmt.Sprintf("* Vulnerable module: %s\n", componentName))
		} else {
			sb.WriteString(fmt.Sprintf("* Affected component: %s\n", componentName))
		}
	}

	// Introduced through
	var dependencyPaths []string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyDependencyPaths); ok {
		dependencyPaths, _ = val.([]string)
	}
	if len(dependencyPaths) > 0 {
		// Get the root package from first path
		firstPath := dependencyPaths[0]
		parts := strings.Split(firstPath, " › ")
		if len(parts) > 1 {
			sb.WriteString(fmt.Sprintf("* Introduced through: %s, %s and others\n", parts[0], parts[1]))
		} else if len(parts) == 1 {
			sb.WriteString(fmt.Sprintf("* Introduced through: %s\n", parts[0]))
		}

		// Detailed paths
		sb.WriteString("### Detailed paths\n")
		for _, path := range dependencyPaths {
			sb.WriteString(fmt.Sprintf("* _Introduced through_: %s\n", path))
		}
	} else if componentName != "" {
		// Fallback if no dependency paths available
		var componentVersion string
		if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentVersion); ok {
			componentVersion, _ = val.(string)
		}
		sb.WriteString(fmt.Sprintf("* Introduced through: %s@%s\n", componentName, componentVersion))
	}

	// Description
	description := issue.GetDescription()
	if description != "" {
		sb.WriteString(description)
	}

	return sb.String()
}

func buildLocation(finding testapi.FindingData, issue testapi.Issue) map[string]interface{} {
	// Default to line 1 for manifest files
	uri := "package.json" // Default, should be determined from locations
	startLine := 1
	var packageName, packageVersion string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentName); ok {
		packageName, _ = val.(string)
	}
	if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentVersion); ok {
		packageVersion, _ = val.(string)
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

func buildFixes(finding testapi.FindingData, issue testapi.Issue) []interface{} {
	var fixedVersions []string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyFixedInVersions); ok {
		fixedVersions, _ = val.([]string)
	}
	if len(fixedVersions) == 0 {
		return nil
	}

	fixedVersion := fixedVersions[0]
	var packageName string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentName); ok {
		packageName, _ = val.(string)
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
