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

// shouldProcessIssue checks if an issue should be processed for SARIF rule generation
func shouldProcessIssue(issue testapi.Issue, findingType testapi.FindingType) bool {
	if issue.GetFindingType() != findingType {
		return false
	}
	return len(issue.GetFindings()) > 0
}

// buildSarifRule constructs a SARIF rule from an issue
func buildSarifRule(issue testapi.Issue, issueID string, findingType testapi.FindingType) map[string]interface{} {
	componentName := getMetadataString(issue, testapi.MetadataKeyComponentName)
	componentVersion := getMetadataString(issue, testapi.MetadataKeyComponentVersion)

	shortDesc := buildShortDescription(issue, componentName)
	fullDesc := buildFullDescription(componentName, componentVersion, issue.GetCVEs())
	helpMarkdown := buildHelpMarkdownGeneric(issue, findingType)
	properties := buildRuleProperties(issue)

	return map[string]interface{}{
		"id":               issueID,
		"shortDescription": shortDesc,
		"fullDescription":  fullDesc,
		"help_text":        "",
		"help_markdown":    helpMarkdown,
		"properties":       properties,
	}
}

// buildShortDescription creates the short description for a SARIF rule
func buildShortDescription(issue testapi.Issue, componentName string) string {
	severity := issue.GetSeverity()
	return fmt.Sprintf("%s severity - %s vulnerability in %s",
		cases.Title(language.English).String(severity),
		issue.GetTitle(),
		componentName)
}

// buildFullDescription creates the full description for a SARIF rule
func buildFullDescription(componentName, componentVersion string, cveIds []string) string {
	fullDesc := fmt.Sprintf("%s@%s", componentName, componentVersion)
	if len(cveIds) > 0 {
		fullDesc = fmt.Sprintf("(%s) %s", strings.Join(cveIds, ", "), fullDesc)
	}
	return fullDesc
}

// buildRuleProperties builds the properties object for a SARIF rule
func buildRuleProperties(issue testapi.Issue) map[string]interface{} {
	tags := []interface{}{"security"}
	for _, cwe := range issue.GetCWEs() {
		tags = append(tags, cwe)
	}

	technology := getMetadataString(issue, testapi.MetadataKeyTechnology)
	if technology != "" {
		tags = append(tags, technology)
	}

	cvssScore := getMetadataFloat(issue, testapi.MetadataKeyCVSSScore)
	return map[string]interface{}{
		"cvssv3_baseScore":  cvssScore,
		"security-severity": fmt.Sprintf("%.1f", cvssScore),
		"tags":              tags,
	}
}

// getMetadataString is a helper to safely extract string metadata
func getMetadataString(issue testapi.Issue, key string) string {
	if val, ok := issue.GetMetadata(key); ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// getMetadataFloat is a helper to safely extract float32 metadata
func getMetadataFloat(issue testapi.Issue, key string) float32 {
	if val, ok := issue.GetMetadata(key); ok {
		if f, ok := val.(float32); ok {
			return f
		}
	}
	return 0.0
}

// GetRulesFromIssues extracts SARIF rules from a list of Issues for a specific finding type.
// Based on the TypeScript implementation in open-source-sarif-output.ts
func GetRulesFromIssues(issuesList []testapi.Issue, t testapi.FindingType) []map[string]interface{} {
	sarifRules := map[string]map[string]interface{}{}

	for _, issue := range issuesList {
		if !shouldProcessIssue(issue, t) {
			continue
		}

		issueID := issue.GetID()
		if issueID == "" || sarifRules[issueID] != nil {
			continue
		}

		sarifRules[issueID] = buildSarifRule(issue, issueID, t)
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
		if !shouldProcessIssue(issue, findingType) {
			continue
		}

		issueID := issue.GetID()
		if issueID == "" {
			continue
		}

		firstFinding := issue.GetFindings()[0]
		sarifResult := buildSarifResult(issue, issueID, firstFinding)
		addFixesIfAvailable(sarifResult, issue, firstFinding)

		results = append(results, sarifResult)
	}

	sortResultsByRuleId(results)
	return results
}

// buildSarifResult constructs a SARIF result object from an issue
func buildSarifResult(issue testapi.Issue, issueID string, firstFinding testapi.FindingData) map[string]interface{} {
	severity := issue.GetSeverity()
	componentName := getMetadataString(issue, testapi.MetadataKeyComponentName)

	message := map[string]interface{}{
		"text": fmt.Sprintf("This file introduces a vulnerable %s package with a %s severity vulnerability.",
			componentName,
			severity),
	}

	location := buildLocation(firstFinding, issue)
	sarifLevel := SeverityToSarifLevel(severity)

	return map[string]interface{}{
		"ruleId":    issueID,
		"level":     sarifLevel,
		"message":   message,
		"locations": []interface{}{location},
	}
}

// addFixesIfAvailable adds fix information to the SARIF result if available
func addFixesIfAvailable(sarifResult map[string]interface{}, issue testapi.Issue, firstFinding testapi.FindingData) {
	isFixable := getMetadataBool(issue, testapi.MetadataKeyIsFixable)
	fixedVersions := getMetadataStrings(issue, testapi.MetadataKeyFixedInVersions)

	if isFixable && len(fixedVersions) > 0 {
		fixes := buildFixes(firstFinding, issue)
		if fixes != nil {
			sarifResult["fixes"] = fixes
		}
	}
}

// getMetadataBool is a helper to safely extract bool metadata
func getMetadataBool(issue testapi.Issue, key string) bool {
	if val, ok := issue.GetMetadata(key); ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

// getMetadataStrings is a helper to safely extract string slice metadata
func getMetadataStrings(issue testapi.Issue, key string) []string {
	if val, ok := issue.GetMetadata(key); ok {
		if strs, ok := val.([]string); ok {
			return strs
		}
	}
	return []string{}
}

// sortResultsByRuleId sorts SARIF results by ruleId for deterministic output
func sortResultsByRuleId(results []map[string]interface{}) {
	sort.Slice(results, func(i, j int) bool {
		ruleIdI, okI := results[i]["ruleId"].(string)
		ruleIdJ, okJ := results[j]["ruleId"].(string)
		if !okI || !okJ {
			return false
		}
		return ruleIdI < ruleIdJ
	})
}

// buildHelpMarkdownGeneric constructs the help markdown section for SARIF rules
func buildHelpMarkdownGeneric(issue testapi.Issue, findingType testapi.FindingType) string {
	var sb strings.Builder

	appendTechnologySection(&sb, issue, findingType)
	componentName := appendComponentSection(&sb, issue, findingType)
	appendDependencyPathsSection(&sb, issue, componentName)
	appendDescriptionSection(&sb, issue)

	return sb.String()
}

// appendTechnologySection adds technology/ecosystem information to the markdown
func appendTechnologySection(sb *strings.Builder, issue testapi.Issue, findingType testapi.FindingType) {
	var technology string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyTechnology); ok {
		if str, ok := val.(string); ok {
			technology = str
		}
	}
	if technology != "" {
		if findingType == testapi.FindingTypeSca {
			sb.WriteString(fmt.Sprintf("* Package Manager: %s\n", technology))
		} else {
			sb.WriteString(fmt.Sprintf("* Technology: %s\n", technology))
		}
	}
}

// appendComponentSection adds component information to the markdown and returns the component name
func appendComponentSection(sb *strings.Builder, issue testapi.Issue, findingType testapi.FindingType) string {
	var componentName string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentName); ok {
		if str, ok := val.(string); ok {
			componentName = str
		}
	}
	if componentName != "" {
		if findingType == testapi.FindingTypeSca {
			sb.WriteString(fmt.Sprintf("* Vulnerable module: %s\n", componentName))
		} else {
			sb.WriteString(fmt.Sprintf("* Affected component: %s\n", componentName))
		}
	}
	return componentName
}

// appendDependencyPathsSection adds dependency path information to the markdown
func appendDependencyPathsSection(sb *strings.Builder, issue testapi.Issue, componentName string) {
	var dependencyPaths []string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyDependencyPaths); ok {
		if strs, ok := val.([]string); ok {
			dependencyPaths = strs
		}
	}

	if len(dependencyPaths) > 0 {
		appendDependencyPathsSummary(sb, dependencyPaths)
		appendDetailedPaths(sb, dependencyPaths)
	} else if componentName != "" {
		appendFallbackIntroduction(sb, issue, componentName)
	}
}

// appendDependencyPathsSummary adds a summary of dependency paths
func appendDependencyPathsSummary(sb *strings.Builder, dependencyPaths []string) {
	firstPath := dependencyPaths[0]
	parts := strings.Split(firstPath, " › ")
	if len(parts) > 1 {
		sb.WriteString(fmt.Sprintf("* Introduced through: %s, %s and others\n", parts[0], parts[1]))
	} else if len(parts) == 1 {
		sb.WriteString(fmt.Sprintf("* Introduced through: %s\n", parts[0]))
	}
}

// appendDetailedPaths adds detailed dependency path information
func appendDetailedPaths(sb *strings.Builder, dependencyPaths []string) {
	sb.WriteString("### Detailed paths\n")
	for _, path := range dependencyPaths {
		sb.WriteString(fmt.Sprintf("* _Introduced through_: %s\n", path))
	}
}

// appendFallbackIntroduction adds a fallback introduction line when no dependency paths are available
func appendFallbackIntroduction(sb *strings.Builder, issue testapi.Issue, componentName string) {
	var componentVersion string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentVersion); ok {
		if str, ok := val.(string); ok {
			componentVersion = str
		}
	}
	sb.WriteString(fmt.Sprintf("* Introduced through: %s@%s\n", componentName, componentVersion))
}

// appendDescriptionSection adds the issue description to the markdown
func appendDescriptionSection(sb *strings.Builder, issue testapi.Issue) {
	description := issue.GetDescription()
	if description != "" {
		sb.WriteString(description)
	}
}

func buildLocation(finding testapi.FindingData, issue testapi.Issue) map[string]interface{} {
	// Default to line 1 for manifest files
	uri := "package.json" // Default, should be determined from locations
	startLine := 1
	var packageName, packageVersion string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentName); ok {
		if str, ok := val.(string); ok {
			packageName = str
		}
	}
	if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentVersion); ok {
		if str, ok := val.(string); ok {
			packageVersion = str
		}
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
		if strs, ok := val.([]string); ok {
			fixedVersions = strs
		}
	}
	if len(fixedVersions) == 0 {
		return nil
	}

	fixedVersion := fixedVersions[0]
	var packageName string
	if val, ok := issue.GetMetadata(testapi.MetadataKeyComponentName); ok {
		if str, ok := val.(string); ok {
			packageName = str
		}
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
