package sarif

import (
	"fmt"
	"strings"

	"github.com/snyk/code-client-go/sarif"

	"github.com/snyk/go-application-framework/internal/ufm_helpers"
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
	case "secrets":
		return "Snyk Secrets"
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
	shortDescription, _ := issue.GetData(testapi.DataKeyRuleShortDescription)
	strShortDescription, ok := shortDescription.(string)
	if ok && strShortDescription != "" {
		return strShortDescription
	}

	componentName, _ := issue.GetData(testapi.DataKeyComponentName)
	severity := issue.GetSeverity()
	title := issue.GetTitle()

	// Capitalize first letter of severity
	if len(severity) > 0 {
		severity = strings.ToUpper(severity[:1]) + severity[1:]
	}

	packageDetails := ""
	if strComponentName, ok := componentName.(string); ok && strComponentName != "" {
		packageDetails = " vulnerability in " + strComponentName
	}

	return fmt.Sprintf("%s severity - %s%s", severity, title, packageDetails)
}

// BuildRuleFullDescription creates the full description for a SARIF rule
func BuildRuleFullDescription(issue testapi.Issue) string {
	componentName, _ := issue.GetData(testapi.DataKeyComponentName)
	componentVersion, _ := issue.GetData(testapi.DataKeyComponentVersion)

	if componentName == nil || componentVersion == nil {
		return ""
	}

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
	if componentName != nil {
		componentNameStr := fmt.Sprintf("%v", componentName)
		return fmt.Sprintf("This file introduces a vulnerable %s package with a %s severity vulnerability.",
			componentNameStr, issue.GetSeverity())
	}

	title := issue.GetTitle()
	return fmt.Sprintf("This file contains a %s severity %s vulnerability.", issue.GetSeverity(), title)
}

// BuildFixFromIssue builds SARIF fix from an issue (nil if the issue is not fixable)
func BuildFixFromIssue(issue testapi.Issue) map[string]string {
	isFixable, ok := issue.GetData(testapi.DataKeyIsFixable)
	if !ok {
		return nil
	}
	if fixable, ok := isFixable.(bool); !ok || !fixable {
		return nil
	}

	fixAttrs := ufm_helpers.GetFixAttributes(issue)
	if fixAttrs == nil || fixAttrs.Action == nil {
		return nil
	}

	if packageName, packageVersion := ufm_helpers.GetDirectPackageUpgradeTarget(fixAttrs); packageName != "" && packageVersion != "" {
		packageAndVersion := fmt.Sprintf("%s@%s", packageName, packageVersion)
		return map[string]string{"description": "Upgrade to " + packageAndVersion, "packageVersion": packageAndVersion}
	}

	if packageName, packageVersion := ufm_helpers.GetDirectPackagePinTarget(fixAttrs); packageName != "" && packageVersion != "" {
		packageAndVersion := fmt.Sprintf("%s@%s", packageName, packageVersion)
		return map[string]string{"description": "Upgrade to " + packageAndVersion, "packageVersion": packageAndVersion}
	}

	return nil
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
		if findingType == testapi.FindingTypeSca || findingType == testapi.FindingTypeLicense {
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
			sb.WriteString(fmt.Sprintf("* Vulnerable module: %s\n", componentName))
		} else if findingType == testapi.FindingTypeLicense {
			sb.WriteString(fmt.Sprintf("* Module: %s\n", componentName))
		} else {
			sb.WriteString(fmt.Sprintf("* Affected component: %s\n", componentName))
		}
	}
	return componentName
}

// appendDependencyPathsSection adds dependency path information to the markdown
func appendDependencyPathsSection(sb *strings.Builder, issue testapi.Issue, componentName string) {
	val, ok := issue.GetData(testapi.DataKeyDependencyPaths)
	if !ok {
		if componentName != "" {
			appendFallbackIntroduction(sb, issue, componentName)
		}
		return
	}

	// Handle new format: [][]Package (structured data)
	if paths, ok := val.([][]testapi.Package); ok {
		if len(paths) > 0 {
			appendDependencyPathsSummaryFromPackages(sb, paths)
			appendDetailedPathsFromPackages(sb, paths)
		}
		return
	}

	// Backward compatibility: [][]string format
	if paths, ok := val.([][]string); ok {
		if len(paths) > 0 {
			appendDependencyPathsSummary(sb, paths)
			appendDetailedPaths(sb, paths)
		}
		return
	}

	// Backward compatibility: []string format (old pre-joined strings)
	if strs, ok := val.([]string); ok {
		if len(strs) > 0 {
			appendDependencyPathsFromStrings(sb, strs)
		}
		return
	}

	// No valid paths found
	if componentName != "" {
		appendFallbackIntroduction(sb, issue, componentName)
	}
}

// appendDependencyPathsSummaryFromPackages writes summary directly without intermediate allocations
func appendDependencyPathsSummaryFromPackages(sb *strings.Builder, paths [][]testapi.Package) {
	if len(paths) == 0 || len(paths[0]) == 0 {
		return
	}

	firstPath := paths[0]
	sb.WriteString("* Introduced through: ")

	// Format first package
	sb.WriteString(firstPath[0].Name)
	sb.WriteByte('@')

	version := firstPath[0].Version
	if version == "" {
		version = "*"
	}
	sb.WriteString(version)

	if len(firstPath) > 2 {
		sb.WriteString(", ")
		sb.WriteString(firstPath[1].Name)
		sb.WriteByte('@')
		sb.WriteString(firstPath[1].Version)
		sb.WriteString(" and others")
	} else if len(firstPath) == 2 {
		sb.WriteString(" and ")
		sb.WriteString(firstPath[1].Name)
		sb.WriteByte('@')
		sb.WriteString(firstPath[1].Version)
	}

	sb.WriteByte('\n')
}

// appendDetailedPathsFromPackages writes paths directly without intermediate strings
func appendDetailedPathsFromPackages(sb *strings.Builder, paths [][]testapi.Package) {
	sb.WriteString("### Detailed paths\n")
	for _, path := range paths {
		sb.WriteString("* _Introduced through_: ")
		for i, pkg := range path {
			if i > 0 {
				sb.WriteString(" › ")
			}
			sb.WriteString(pkg.Name)
			sb.WriteByte('@')
			if pkg.Version == "" {
				sb.WriteString("*")
			} else {
				sb.WriteString(pkg.Version)
			}
		}
		sb.WriteByte('\n')
	}
}

// appendDependencyPathsSummary adds a summary of dependency paths ([][]string format)
func appendDependencyPathsSummary(sb *strings.Builder, dependencyPaths [][]string) {
	if len(dependencyPaths) == 0 || len(dependencyPaths[0]) == 0 {
		return
	}

	firstPath := dependencyPaths[0]
	sb.WriteString("* Introduced through: ")
	sb.WriteString(firstPath[0])

	if len(firstPath) > 2 {
		sb.WriteString(", ")
		sb.WriteString(firstPath[1])
		sb.WriteString(" and others")
	} else if len(firstPath) == 2 {
		sb.WriteString(" and ")
		sb.WriteString(firstPath[1])
	}

	sb.WriteByte('\n')
}

// appendDetailedPaths adds detailed dependency path information ([][]string format)
func appendDetailedPaths(sb *strings.Builder, dependencyPaths [][]string) {
	sb.WriteString("### Detailed paths\n")
	for _, pathParts := range dependencyPaths {
		sb.WriteString("* _Introduced through_: ")
		for i, part := range pathParts {
			if i > 0 {
				sb.WriteString(" › ")
			}
			sb.WriteString(part)
		}
		sb.WriteByte('\n')
	}
}

// appendDependencyPathsFromStrings handles old format (pre-joined strings)
func appendDependencyPathsFromStrings(sb *strings.Builder, paths []string) {
	if len(paths) == 0 {
		return
	}

	// Summary from first path
	firstPath := paths[0]
	parts := strings.SplitN(firstPath, " › ", 3) // Only split what we need
	sb.WriteString("* Introduced through: ")
	sb.WriteString(parts[0])
	if len(parts) > 2 {
		sb.WriteString(", ")
		sb.WriteString(parts[1])
		sb.WriteString(" and others")
	} else if len(parts) == 2 {
		sb.WriteString(" and ")
		sb.WriteString(parts[1])
	}
	sb.WriteByte('\n')

	// Detailed paths
	sb.WriteString("### Detailed paths\n")
	for _, pathStr := range paths {
		sb.WriteString("* _Introduced through_: ")
		sb.WriteString(pathStr)
		sb.WriteByte('\n')
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

type regionData struct {
	StartLine   int  `json:"startLine"`
	StartColumn *int `json:"startColumn,omitempty"`
	EndLine     *int `json:"endLine,omitempty"`
	EndColumn   *int `json:"endColumn,omitempty"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           regionData       `json:"region"`
}

type logicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
}

type sarifLocation struct {
	PhysicalLocation *physicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []logicalLocation `json:"logicalLocations,omitempty"`
}

// BuildLocations constructs SARIF location objects from issue finding data
// Returns a slice of location objects, each containing physical and logical locations
func BuildLocations(issue testapi.Issue, targetFile string) []sarifLocation {
	packageName, packageVersion := getPackageNameAndVersionFromIssue(issue)
	findings := issue.GetFindings()
	findingType := issue.GetFindingType()
	if len(findings) == 0 {
		return nil
	}

	// SCA findings have only one location, so we can return it immediately
	if findingType == testapi.FindingTypeSca {
		scaFindingLocation := sarifLocation{
			LogicalLocations: []logicalLocation{buildLogicalLocation(packageName, packageVersion)},
		}
		if targetFile != "" {
			pLocation := buildPhysicalLocation(targetFile, regionData{StartLine: 1})
			scaFindingLocation.PhysicalLocation = &pLocation
		}
		return []sarifLocation{scaFindingLocation}
	}

	// track seen locations to prevent duplicates
	var locations []sarifLocation
	seen := make(map[string]bool)

	for _, finding := range findings {
		sLocations := buildSarifLocations(*finding, targetFile, packageName, packageVersion)

		for _, sLoc := range sLocations {
			key := ""

			if len(sLoc.LogicalLocations) > 0 {
				key += fmt.Sprintf("log:%s", sLoc.LogicalLocations[0].FullyQualifiedName)
			}

			if sLoc.PhysicalLocation != nil {
				key += fmt.Sprintf("phys:%s:%d", sLoc.PhysicalLocation.ArtifactLocation.URI, sLoc.PhysicalLocation.Region.StartLine)
				if sLoc.PhysicalLocation.Region.EndLine != nil {
					key += fmt.Sprintf(":%d", *sLoc.PhysicalLocation.Region.EndLine)
				}
				if sLoc.PhysicalLocation.Region.StartColumn != nil {
					key += fmt.Sprintf(":%d", *sLoc.PhysicalLocation.Region.StartColumn)
				}
				if sLoc.PhysicalLocation.Region.EndColumn != nil {
					key += fmt.Sprintf(":%d", *sLoc.PhysicalLocation.Region.EndColumn)
				}
			}

			if !seen[key] {
				seen[key] = true
				locations = append(locations, sLoc)
			}
		}
	}

	return locations
}

// buildSarifLocations extracts physical and logical locations from finding data
// Returns a slice of location objects, each containing physical and logical locations
func buildSarifLocations(finding testapi.FindingData, targetFile string, packageName string, packageVersion string) []sarifLocation {
	var sLocations []sarifLocation

	// try to extract actual file path and package version from locations
	hasLocations := finding.Attributes != nil && len(finding.Attributes.Locations) > 0

	if hasLocations && targetFile == "" {
		for _, loc := range finding.Attributes.Locations {
			sLoc := buildSarifLocationFromLoc(loc, packageName, packageVersion)
			if sLoc.PhysicalLocation != nil {
				sLocations = append(sLocations, sLoc)
			}
		}
	}

	// if no locations were generated
	if len(sLocations) == 0 {
		if fallback := buildFallbackSarifLocation(targetFile, packageName, packageVersion); fallback != nil {
			sLocations = append(sLocations, *fallback)
		}
	}

	return sLocations
}

// buildSarifLocationFromLoc extracts location data from a finding location
// Returns a location object with physical and logical locations
func buildSarifLocationFromLoc(loc testapi.FindingLocation, packageName string, packageVersion string) sarifLocation {
	pName, pVersion := packageName, packageVersion

	pkgLoc, err := loc.AsPackageLocation()
	if err == nil {
		if pkgLoc.Package.Name != "" {
			pName = pkgLoc.Package.Name
		}
		if pkgLoc.Package.Version != "" {
			pVersion = pkgLoc.Package.Version
		}
	}

	if pName != "" || pVersion != "" {
		return sarifLocation{LogicalLocations: []logicalLocation{buildLogicalLocation(pName, pVersion)}}
	}

	return buildSarifLocationFromSourceLoc(loc)
}

// buildSarifLocationFromSourceLoc extracts location data from a source location
// Returns a location object with physical location only
func buildSarifLocationFromSourceLoc(loc testapi.FindingLocation) sarifLocation {
	region := regionData{StartLine: 1}

	sourceLoc, err := loc.AsSourceLocation()
	if err != nil || sourceLoc.FilePath == "" {
		return sarifLocation{}
	}

	region.StartLine = sourceLoc.FromLine
	if sourceLoc.FromColumn != nil {
		region.StartColumn = sourceLoc.FromColumn
	}
	if sourceLoc.ToLine != nil {
		region.EndLine = sourceLoc.ToLine
	}
	if sourceLoc.ToColumn != nil {
		region.EndColumn = sourceLoc.ToColumn
	}

	pLocation := buildPhysicalLocation(sourceLoc.FilePath, region)
	return sarifLocation{PhysicalLocation: &pLocation}
}

// buildFallbackSarifLocation creates a fallback location when no specific locations are found
// Returns a location object with either physical or logical location, or nil if neither is provided
func buildFallbackSarifLocation(targetFile string, packageName string, packageVersion string) *sarifLocation {
	var pLoc *physicalLocation
	var lLocs []logicalLocation

	if len(targetFile) > 0 {
		pLocation := buildPhysicalLocation(targetFile, regionData{StartLine: 1})
		pLoc = &pLocation
	}

	if packageName != "" || packageVersion != "" {
		lLocs = []logicalLocation{buildLogicalLocation(packageName, packageVersion)}
	}

	if pLoc != nil || len(lLocs) > 0 {
		return &sarifLocation{PhysicalLocation: pLoc, LogicalLocations: lLocs}
	}
	return nil
}

// buildPhysicalLocation creates a physical location object with the given URI and region
func buildPhysicalLocation(uri string, region regionData) physicalLocation {
	return physicalLocation{
		ArtifactLocation: artifactLocation{
			URI: uri,
		},
		Region: region,
	}
}

// buildLogicalLocation creates a logical location object with the given package name and version
func buildLogicalLocation(packageName string, packageVersion string) logicalLocation {
	return logicalLocation{
		FullyQualifiedName: fmt.Sprintf("%s@%s", packageName, packageVersion),
	}
}

// getPackageNameAndVersionFromIssue extracts package name and version from issue data
// Returns the package name and version, or empty strings if not found
func getPackageNameAndVersionFromIssue(issue testapi.Issue) (packageName, packageVersion string) {
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
	return packageName, packageVersion
}
