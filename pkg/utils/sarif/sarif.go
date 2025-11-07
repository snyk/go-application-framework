package sarif

import (
	"fmt"
	"strings"

	"github.com/snyk/code-client-go/sarif"

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

// BuildHelpMarkdown constructs the help markdown section for SARIF rules
func BuildHelpMarkdown(issue testapi.Issue, findingType testapi.FindingType) string {
	var sb strings.Builder

	appendTechnologySection(&sb, issue, findingType)
	componentName := appendComponentSection(&sb, issue, findingType)
	appendDependencyPathsSection(&sb, issue, componentName)
	appendDescriptionSection(&sb, issue)

	return sb.String()
}

// BuildRuleShortDescription creates the short description for a SARIF rule
func BuildRuleShortDescription(issue testapi.Issue) string {
	componentName, _ := issue.GetData(testapi.DataKeyComponentName)
	componentNameStr := fmt.Sprintf("%v", componentName)
	if componentNameStr == "" || componentNameStr == "<nil>" {
		componentNameStr = "package"
	}
	severity := issue.GetSeverity()
	title := issue.GetTitle()

	// Capitalize first letter of severity
	if len(severity) > 0 {
		severity = strings.ToUpper(severity[:1]) + severity[1:]
	}

	return fmt.Sprintf("%s severity - %s vulnerability in %s", severity, title, componentNameStr)
}

// BuildRuleFullDescription creates the full description for a SARIF rule
func BuildRuleFullDescription(issue testapi.Issue) string {
	componentName, _ := issue.GetData(testapi.DataKeyComponentName)
	componentVersion, _ := issue.GetData(testapi.DataKeyComponentVersion)

	componentNameStr := fmt.Sprintf("%v", componentName)
	componentVersionStr := fmt.Sprintf("%v", componentVersion)

	fullDesc := fmt.Sprintf("%s@%s", componentNameStr, componentVersionStr)
	cveIds := issue.GetCVEs()
	if len(cveIds) > 0 {
		fullDesc = fmt.Sprintf("(%s) %s", strings.Join(cveIds, ", "), fullDesc)
	}
	return fullDesc
}

// BuildRuleTags creates the tags array for a SARIF rule
func BuildRuleTags(issue testapi.Issue) []interface{} {
	tags := []interface{}{"security"}
	for _, cwe := range issue.GetCWEs() {
		tags = append(tags, cwe)
	}

	technology, ok := issue.GetData(testapi.DataKeyTechnology)
	if ok {
		if techStr, ok := technology.(string); ok && techStr != "" {
			tags = append(tags, techStr)
		}
	}

	return tags
}

// GetRuleCVSSScore extracts the CVSS score from issue metadata
func GetRuleCVSSScore(issue testapi.Issue) float32 {
	cvssScore, ok := issue.GetData(testapi.DataKeyCVSSScore)
	if !ok {
		return -1.0 // Sentinel value indicating no score available
	}
	if score, ok := cvssScore.(float32); ok {
		if score == 0.0 {
			return -1.0 // Treat 0 as no score (e.g., for license issues)
		}
		return score
	}
	return -1.0
}

// FormatIssueMessage creates the SARIF message text for an issue
func FormatIssueMessage(issue testapi.Issue) string {
	componentName, _ := issue.GetData(testapi.DataKeyComponentName)
	componentNameStr := fmt.Sprintf("%v", componentName)
	if componentNameStr == "" || componentNameStr == "<nil>" {
		componentNameStr = "package"
	}

	return fmt.Sprintf("This file introduces a vulnerable %s package with a %s severity vulnerability.",
		componentNameStr, issue.GetSeverity())
}

// BuildFixesFromIssue builds SARIF fixes array from issue
// Checks metadata to determine if fixes should be shown, then delegates to BuildFixes
func BuildFixesFromIssue(issue testapi.Issue) []interface{} {
	findings := issue.GetFindings()
	if len(findings) == 0 {
		return nil
	}

	// Check metadata to determine if fixes should be shown (maintains backward compatibility)
	isFixable, ok := issue.GetData(testapi.DataKeyIsFixable)
	if !ok {
		return nil
	}
	isFixableBool, ok := isFixable.(bool)
	if !ok || !isFixableBool {
		return nil
	}

	fixedVersionsVal, ok := issue.GetData(testapi.DataKeyFixedInVersions)
	if !ok {
		return nil
	}
	fixedVersions, ok := fixedVersionsVal.([]string)
	if !ok || len(fixedVersions) == 0 {
		return nil
	}

	// Use the existing buildFixes logic
	return BuildFixes(findings[0])
}

// appendTechnologySection adds technology/ecosystem information to the markdown
func appendTechnologySection(sb *strings.Builder, issue testapi.Issue, findingType testapi.FindingType) {
	var technology string
	if val, ok := issue.GetData(testapi.DataKeyTechnology); ok {
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
	if val, ok := issue.GetData(testapi.DataKeyComponentName); ok {
		if str, ok := val.(string); ok {
			componentName = str
		}
	}
	if componentName != "" {
		if findingType == testapi.FindingTypeSca {
			// Check if this is a license issue (ID starts with "snyk:lic:")
			issueID := issue.GetID()
			if len(issueID) >= 9 && issueID[:9] == "snyk:lic:" {
				sb.WriteString(fmt.Sprintf("* Module: %s\n", componentName))
			} else {
				sb.WriteString(fmt.Sprintf("* Vulnerable module: %s\n", componentName))
			}
		} else {
			sb.WriteString(fmt.Sprintf("* Affected component: %s\n", componentName))
		}
	}
	return componentName
}

// appendDependencyPathsSection adds dependency path information to the markdown
func appendDependencyPathsSection(sb *strings.Builder, issue testapi.Issue, componentName string) {
	var dependencyPaths [][]string
	if val, ok := issue.GetData(testapi.DataKeyDependencyPaths); ok {
		// Handle new format: [][]Package (structured data)
		if paths, ok := val.([][]testapi.Package); ok {
			for _, path := range paths {
				formattedPath := make([]string, len(path))
				for i, pkg := range path {
					formattedPath[i] = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
				}
				dependencyPaths = append(dependencyPaths, formattedPath)
			}
		} else if paths, ok := val.([][]string); ok {
			// Backward compatibility: [][]string format
			dependencyPaths = paths
		} else if strs, ok := val.([]string); ok {
			// Backward compatibility: convert old format (pre-joined strings) to new format
			for _, pathStr := range strs {
				parts := strings.Split(pathStr, " › ")
				dependencyPaths = append(dependencyPaths, parts)
			}
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
func appendDependencyPathsSummary(sb *strings.Builder, dependencyPaths [][]string) {
	if len(dependencyPaths) == 0 {
		return
	}

	firstPath := dependencyPaths[0]
	introduction := "* Introduced through: %s\n"

	if len(firstPath) == 0 {
		return
	}

	dependencyPath := firstPath[0]
	if len(firstPath) > 2 {
		dependencyPath = fmt.Sprintf("%s, %s and others", firstPath[0], firstPath[1])
	} else if len(firstPath) == 2 {
		dependencyPath = fmt.Sprintf("%s and %s", firstPath[0], firstPath[1])
	}
	fmt.Fprintf(sb, introduction, dependencyPath)
}

// appendDetailedPaths adds detailed dependency path information
func appendDetailedPaths(sb *strings.Builder, dependencyPaths [][]string) {
	sb.WriteString("### Detailed paths\n")
	for _, pathParts := range dependencyPaths {
		formattedPath := strings.Join(pathParts, " › ")
		sb.WriteString(fmt.Sprintf("* _Introduced through_: %s\n", formattedPath))
	}
}

// appendFallbackIntroduction adds a fallback introduction line when no dependency paths are available
func appendFallbackIntroduction(sb *strings.Builder, issue testapi.Issue, componentName string) {
	var componentVersion string
	if val, ok := issue.GetData(testapi.DataKeyComponentVersion); ok {
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
		sb.WriteString(strings.ReplaceAll(description, "##", "#"))
	}
}

// BuildLocation constructs a SARIF location object from issue data
func BuildLocation(issue testapi.Issue) map[string]interface{} {
	// Extract first finding from issue
	findings := issue.GetFindings()
	if len(findings) == 0 {
		return nil
	}
	finding := findings[0]

	// Default to line 1 for manifest files
	uri := "package.json" // Default, should be determined from locations
	startLine := 1
	var packageName, packageVersion string
	if val, ok := issue.GetData(testapi.DataKeyComponentName); ok {
		if str, ok := val.(string); ok {
			packageName = str
		}
	}
	if val, ok := issue.GetData(testapi.DataKeyComponentVersion); ok {
		if str, ok := val.(string); ok {
			packageVersion = str
		}
	}

	// Try to extract actual file path and package version from locations
	if finding.Attributes != nil && len(finding.Attributes.Locations) > 0 {
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

// BuildFixes extracts fix information from a finding's relationship data
func BuildFixes(finding *testapi.FindingData) []interface{} {
	if finding.Relationships == nil || finding.Relationships.Fix == nil || finding.Relationships.Fix.Data == nil {
		return nil
	}

	fixData := finding.Relationships.Fix.Data
	if fixData.Attributes == nil || fixData.Attributes.Action == nil {
		return nil
	}

	upgradeAdvice, err := fixData.Attributes.Action.AsUpgradePackageAdvice()
	if err != nil {
		return nil
	}

	packageName := upgradeAdvice.PackageName
	if packageName == "" {
		return nil
	}

	// TODO: where to get the uri from?
	uri := "package.json"
	startLine := 1
	if len(finding.Attributes.Locations) > 0 {
		loc := finding.Attributes.Locations[0]

		if sourceLoc, err := loc.AsSourceLocation(); err == nil && sourceLoc.FilePath != "" {
			uri = sourceLoc.FilePath
			startLine = sourceLoc.FromLine
		}
	}

	var fixes []interface{}
	for _, upgradePath := range upgradeAdvice.UpgradePaths {
		if len(upgradePath.DependencyPath) < 2 {
			continue
		}

		// Get the direct dependency to upgrade (second package in path, after root)
		directDependency := upgradePath.DependencyPath[1]
		directPackageName := directDependency.Name
		directVersion := directDependency.Version

		packageVersion := fmt.Sprintf("%s@%s", directPackageName, directVersion)

		// Always show as an upgrade, regardless of isDrop
		// isDrop indicates that the vulnerable dependency will be removed from the tree,
		// but the fix action is still to upgrade the direct dependency
		fixDescription := fmt.Sprintf("Upgrade to %s", packageVersion)

		fix := map[string]interface{}{
			"description": map[string]interface{}{
				"text": fixDescription,
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
								"text": packageVersion,
							},
						},
					},
				},
			},
		}

		fixes = append(fixes, fix)
	}

	// Only one or no upgrade paths are expected
	if len(fixes) > 0 {
		return []interface{}{fixes[0]}
	}

	return nil
}
