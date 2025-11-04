package testapi

import (
	"context"
	"fmt"
	"strings"
)

// Metadata keys for common issue properties (case-insensitive)
const (
	// MetadataKeyComponent is the key for accessing the component information (name and version)
	// Value type: map[string]string with keys "name" and "version"
	MetadataKeyComponent = "component"

	// MetadataKeyComponentName is the key for accessing just the component name
	// Value type: string
	MetadataKeyComponentName = "component-name"

	// MetadataKeyComponentVersion is the key for accessing just the component version
	// Value type: string
	MetadataKeyComponentVersion = "component-version"

	// MetadataKeyTechnology is the key for the technology/ecosystem
	// For SCA: package manager (e.g., "npm", "maven")
	// For SAST: language/framework (e.g., "javascript", "python")
	// Value type: string
	MetadataKeyTechnology = "technology"

	// MetadataKeyCVSSScore is the key for CVSS base score
	// Value type: float32
	MetadataKeyCVSSScore = "cvss-score"

	// MetadataKeyIsFixable is the key for whether a fix is available
	// Value type: bool
	MetadataKeyIsFixable = "is-fixable"

	// MetadataKeyFixedInVersions is the key for versions that fix this issue
	// Value type: []string
	MetadataKeyFixedInVersions = "fixed-in-versions"

	// MetadataKeyDependencyPaths is the key for dependency paths (SCA findings)
	// Value type: []string
	MetadataKeyDependencyPaths = "dependency-paths"
)

//go:generate go run github.com/golang/mock/mockgen -source=issues.go -destination=../mocks/issues.go -package=mocks

// Issue defines the interface for accessing a single aggregated security issue.
// An issue represents a cohesive security problem derived from one or more related findings.
// This interface is designed to be easily convertible to snyk-ls Issue format.
// It supports all finding types (SCA, SAST, DAST, Other) with both general and type-specific methods.
type Issue interface {
	// === General Methods (applicable to all finding types) ===

	// GetFindings returns all findings that are part of this issue.
	GetFindings() []FindingData

	// GetFindingType returns the finding type of this issue.
	// All findings in an issue should have the same finding type.
	GetFindingType() FindingType

	// GetProblems returns all problems from all findings in this issue.
	GetProblems() []Problem

	// GetPrimaryProblem returns the primary problem for this issue.
	// For SCA findings, this would be the SnykVulnProblem.
	// For other finding types, this may be a CWE, CVE, or rule-based problem.
	// Returns nil if no primary problem can be determined.
	GetPrimaryProblem() *Problem

	// GetID returns the unique identifier for this issue.
	// For SCA findings, this is typically the vulnerability ID.
	// For SAST findings, this may be the rule ID or finding key.
	// For other finding types, this may be derived from the finding key.
	GetID() string

	// GetSeverity returns the severity of this issue.
	// For SCA findings, this comes from the SnykVulnProblem.
	// For other finding types, this comes from the Rating attribute.
	// Returns empty string if severity cannot be determined.
	GetSeverity() string

	// GetTitle returns the title of this issue.
	// Typically comes from the first finding's title attribute.
	GetTitle() string

	// GetDescription returns the description of this issue.
	// Typically comes from the first finding's description attribute.
	GetDescription() string

	// GetCWEs returns the CWE identifiers associated with this issue.
	// Extracted from CWE problems across all findings.
	GetCWEs() []string

	// GetCVEs returns the CVE identifiers associated with this issue.
	// Extracted from CVE problems across all findings.
	GetCVEs() []string

	// GetSourceLocations returns all source file locations for this issue.
	// For SAST findings, this contains file paths and line numbers.
	// For SCA findings, this may contain manifest file locations.
	// Returns empty slice if no source locations are found.
	GetSourceLocations() []SourceLocation

	// GetRuleID returns the rule ID for this issue, if applicable.
	// For SAST findings, this may be extracted from problems or finding attributes.
	// For SCA findings, this is typically the vulnerability ID.
	// Returns empty string if not applicable or not found.
	GetRuleID() string

	// GetRiskScore returns the risk score (0-100) for this issue.
	// Risk score is calculated based on severity, exploitability, and asset criticality.
	// Extracted from the Risk attribute of findings.
	// Returns 0 if not available.
	GetRiskScore() uint16

	// GetEffectiveSeverity returns the effective severity, which may be overwritten by policy.
	// This is the severity that should be used for prioritization and display.
	// For SCA findings, this comes from the SnykVulnProblem or policy modifications.
	// For other finding types, this comes from Rating or policy modifications.
	// Returns empty string if not available.
	GetEffectiveSeverity() string

	// GetReachability returns the reachability assessment for this issue.
	// Indicates whether vulnerable code is reachable in the application.
	// Returns nil if reachability information is not available.
	GetReachability() *ReachabilityEvidence

	// GetMetadata returns metadata value for the given key (case-insensitive).
	// Returns the value and true if found, nil and false otherwise.
	// Use the MetadataKey* constants for well-known keys.
	// Callers should perform type assertions on the returned interface{}.
	GetMetadata(key string) (interface{}, bool)
}

// NewIssuesFromTestResult creates a list of Issues from a TestResult.
// Findings are automatically grouped into cohesive security issues based on their type and characteristics.
// For SCA findings, issues are grouped by vulnerability ID.
// For other finding types, issues are grouped by finding key.
func NewIssuesFromTestResult(ctx context.Context, testResult TestResult) ([]Issue, error) {
	if testResult == nil {
		return nil, &IssueError{Message: "testResult cannot be nil"}
	}

	// Extract findings
	findings, _, err := testResult.Findings(ctx)
	if err != nil {
		return nil, &IssueError{Message: "failed to extract findings", Cause: err}
	}

	if len(findings) == 0 {
		return []Issue{}, nil
	}

	// Determine grouping strategy based on finding types
	// Use vulnerability-based grouping for SCA findings, key-based for others
	grouper := selectGrouper(findings)

	// Group findings into issues
	groups := grouper.groupFindings(findings)

	// Create Issue for each group
	issuesList := make([]Issue, 0, len(groups))
	for _, group := range groups {
		issue, err := newIssue(group)
		if err != nil {
			continue // Skip invalid groups
		}
		issuesList = append(issuesList, issue)
	}

	return issuesList, nil
}

// selectGrouper chooses the appropriate grouping strategy based on finding types.
func selectGrouper(findings []FindingData) issueGrouper {
	// Check if we have SCA findings - use vulnerability-based grouping
	for _, finding := range findings {
		if finding.Attributes != nil && finding.Attributes.FindingType == FindingTypeSca {
			return &vulnerabilityIssueGrouper{}
		}
	}
	// Default to key-based grouping
	return &keyBasedIssueGrouper{}
}

// issueGrouper defines the interface for grouping findings into cohesive security issues.
// This is an internal interface - grouping logic is hidden from users.
type issueGrouper interface {
	groupFindings(findings []FindingData) [][]FindingData
}

// vulnerabilityIssueGrouper groups findings by vulnerability ID for SCA findings.
// Findings with the same vulnerability ID are grouped together as a single issue.
type vulnerabilityIssueGrouper struct{}

func (g *vulnerabilityIssueGrouper) groupFindings(findings []FindingData) [][]FindingData {
	groups := make(map[string][]FindingData)

	for _, finding := range findings {
		if finding.Attributes == nil {
			continue
		}

		// Extract vulnerability ID from problems
		vulnID := g.extractVulnerabilityID(finding)
		if vulnID == "" {
			// If no vulnerability ID found, treat each finding as its own issue
			vulnID = g.getUniqueKey(finding)
		}

		groups[vulnID] = append(groups[vulnID], finding)
	}

	result := make([][]FindingData, 0, len(groups))
	for _, group := range groups {
		result = append(result, group)
	}

	return result
}

func (g *vulnerabilityIssueGrouper) extractVulnerabilityID(finding FindingData) string {
	for _, problem := range finding.Attributes.Problems {
		discriminator, err := problem.Discriminator()
		if err != nil {
			continue
		}

		if discriminator == "snyk_vuln" {
			vulnProblem, err := problem.AsSnykVulnProblem()
			if err == nil {
				return vulnProblem.Id
			}
		}
	}
	return ""
}

func (g *vulnerabilityIssueGrouper) getUniqueKey(finding FindingData) string {
	if finding.Id != nil {
		return finding.Id.String()
	}
	if finding.Attributes != nil {
		return finding.Attributes.Key
	}
	return ""
}

// keyBasedIssueGrouper groups findings by their Key attribute.
// Findings with the same key are grouped together as a single issue.
type keyBasedIssueGrouper struct{}

func (g *keyBasedIssueGrouper) groupFindings(findings []FindingData) [][]FindingData {
	groups := make(map[string][]FindingData)

	for _, finding := range findings {
		if finding.Attributes == nil {
			continue
		}

		key := finding.Attributes.Key
		if key == "" {
			// If no key, use finding ID as fallback
			if finding.Id != nil {
				key = finding.Id.String()
			} else {
				continue
			}
		}

		groups[key] = append(groups[key], finding)
	}

	result := make([][]FindingData, 0, len(groups))
	for _, group := range groups {
		result = append(result, group)
	}

	return result
}

// issue is the concrete implementation of the Issue interface.
type issue struct {
	findings          []FindingData
	findingType       FindingType
	problems          []Problem
	primaryProblem    *Problem
	id                string
	severity          string
	effectiveSeverity string
	cwes              []string
	cves              []string
	title             string
	description       string
	snykVulnProblem   *SnykVulnProblem
	sourceLocations   []SourceLocation
	ruleID            string
	riskScore         uint16
	reachability      *ReachabilityEvidence
	metadata          map[string]interface{} // case-insensitive key storage (lowercase keys)
}

// GetFindings returns all findings that are part of this issue.
func (i *issue) GetFindings() []FindingData {
	return i.findings
}

// GetFindingType returns the finding type of this issue.
func (i *issue) GetFindingType() FindingType {
	return i.findingType
}

// GetProblems returns all problems from all findings in this issue.
func (i *issue) GetProblems() []Problem {
	return i.problems
}

// GetPrimaryProblem returns the primary problem for this issue.
func (i *issue) GetPrimaryProblem() *Problem {
	return i.primaryProblem
}

// GetID returns the unique identifier for this issue.
func (i *issue) GetID() string {
	return i.id
}

// GetSeverity returns the severity of this issue.
func (i *issue) GetSeverity() string {
	return i.severity
}


// GetCWEs returns the CWE identifiers associated with this issue.
func (i *issue) GetCWEs() []string {
	return i.cwes
}

// GetCVEs returns the CVE identifiers associated with this issue.
func (i *issue) GetCVEs() []string {
	return i.cves
}

// GetTitle returns the title of this issue.
func (i *issue) GetTitle() string {
	return i.title
}

// GetDescription returns the description of this issue.
func (i *issue) GetDescription() string {
	return i.description
}

// GetMetadata returns metadata value for the given key (case-insensitive).
func (i *issue) GetMetadata(key string) (interface{}, bool) {
	if i.metadata == nil {
		return nil, false
	}
	value, ok := i.metadata[strings.ToLower(key)]
	return value, ok
}

// GetSourceLocations returns all source file locations for this issue.
func (i *issue) GetSourceLocations() []SourceLocation {
	return i.sourceLocations
}

// GetRuleID returns the rule ID for this issue, if applicable.
func (i *issue) GetRuleID() string {
	return i.ruleID
}

// GetRiskScore returns the risk score (0-100) for this issue.
func (i *issue) GetRiskScore() uint16 {
	return i.riskScore
}

// GetEffectiveSeverity returns the effective severity, which may be overwritten by policy.
func (i *issue) GetEffectiveSeverity() string {
	if i.effectiveSeverity != "" {
		return i.effectiveSeverity
	}
	// Fallback to regular severity if effective severity not set
	return i.severity
}

// GetReachability returns the reachability assessment for this issue.
func (i *issue) GetReachability() *ReachabilityEvidence {
	return i.reachability
}

// NewIssueFromFindings creates a single Issue instance from a group of related findings.
// This is a helper function for creating issues from pre-grouped findings.
func NewIssueFromFindings(findings []FindingData) (Issue, error) {
	return newIssue(findings)
}

// newIssue creates a single Issue instance from a group of related findings.
func newIssue(findings []FindingData) (Issue, error) {
	if len(findings) == 0 {
		return nil, &IssueError{Message: "findings cannot be empty"}
	}

	// All findings in an issue should have the same finding type
	var findingType FindingType
	var allProblems []Problem
	var primaryProblem *Problem
	var firstFinding *FindingData

	// Extract metadata from findings
	var cwes []string
	var cves []string
	var id string
	var severity string
	var effectiveSeverity string
	var ecosystem string
	var title string
	var description string
	var packageName string
	var packageVersion string
	var cvssScore float32
	var isFixable bool
	var fixedInVersions []string
	var dependencyPaths []string
	var snykVulnProblem *SnykVulnProblem
	var sourceLocations []SourceLocation
	var ruleID string
	var riskScore uint16
	var reachability *ReachabilityEvidence

	for _, finding := range findings {
		if finding.Attributes == nil {
			continue
		}

		// Set finding type from first finding
		if findingType == "" {
			findingType = finding.Attributes.FindingType
			firstFinding = &finding
			title = finding.Attributes.Title
			description = finding.Attributes.Description
		}

		// Collect problems
		allProblems = append(allProblems, finding.Attributes.Problems...)

		// Extract source locations from locations
		for _, location := range finding.Attributes.Locations {
			locationDiscriminator, err := location.Discriminator()
			if err != nil {
				continue
			}
			if locationDiscriminator == "source" {
				sourceLoc, err := location.AsSourceLocation()
				if err == nil {
					sourceLocations = append(sourceLocations, sourceLoc)
				}
			}
		}

		// Extract severity from Rating if not already set (for non-SCA findings)
		if severity == "" && finding.Attributes.Rating.Severity != "" {
			severity = string(finding.Attributes.Rating.Severity)
		}

		// Extract risk score from Risk attribute
		if finding.Attributes.Risk.RiskScore != nil && riskScore == 0 {
			riskScore = finding.Attributes.Risk.RiskScore.Value
		}

		// Extract effective severity from policy modifications if available
		// Policy modifications may override the original severity
		if finding.Attributes.PolicyModifications != nil {
			for _, mod := range *finding.Attributes.PolicyModifications {
				// Check if severity was modified (pointer would be "/rating/severity")
				if mod.Pointer == "/rating/severity" && mod.Prior != nil {
					// The current severity is the effective one (after policy modification)
					// Store it as effective severity
					if effectiveSeverity == "" && finding.Attributes.Rating.Severity != "" {
						effectiveSeverity = string(finding.Attributes.Rating.Severity)
					}
				}
			}
		}

		// Extract reachability evidence
		if reachability == nil {
			for _, ev := range finding.Attributes.Evidence {
				discriminator, err := ev.Discriminator()
				if err != nil {
					continue
				}
				if discriminator == "reachability" {
					reachEv, err := ev.AsReachabilityEvidence()
					if err == nil {
						reachability = &reachEv
						break
					}
				}
			}
		}

		// Extract dependency paths from evidence
		for _, ev := range finding.Attributes.Evidence {
			discriminator, err := ev.Discriminator()
			if err != nil {
				continue
			}
			if discriminator == "dependency_path" {
				depPath, err := ev.AsDependencyPathEvidence()
				if err == nil {
					var pathParts []string
					for _, dep := range depPath.Path {
						pathParts = append(pathParts, fmt.Sprintf("%s@%s", dep.Name, dep.Version))
					}
					if len(pathParts) > 0 {
						dependencyPaths = append(dependencyPaths, strings.Join(pathParts, " › "))
					}
				}
			}
		}

		// Extract package name/version from locations
		for _, location := range finding.Attributes.Locations {
			locationDiscriminator, err := location.Discriminator()
			if err != nil {
				continue
			}
			if locationDiscriminator == "package" {
				pkgLoc, err := location.AsPackageLocation()
				if err == nil {
					if packageName == "" {
						packageName = pkgLoc.Package.Name
					}
					if packageVersion == "" {
						packageVersion = pkgLoc.Package.Version
					}
				}
			}
		}

		// Extract CVE and CWE IDs, and determine primary problem
		for _, problem := range finding.Attributes.Problems {
			discriminator, err := problem.Discriminator()
			if err != nil {
				continue
			}

			switch discriminator {
			case "snyk_vuln":
				// Always use the first snyk_vuln problem found for ID and metadata
				// This ensures we use the vulnerability ID even if grouping used a fallback key
				vulnProblem, err := problem.AsSnykVulnProblem()
				if err == nil {
					if primaryProblem == nil {
						primaryProblem = &problem
						snykVulnProblem = &vulnProblem
					}
					// Always set ID from vulnerability ID if available (overrides any fallback)
					if vulnProblem.Id != "" {
						id = vulnProblem.Id
					}
					// Set severity and other metadata from first vuln problem
					if severity == "" {
						severity = string(vulnProblem.Severity)
					}
					if cvssScore == 0.0 {
						cvssScore = float32(vulnProblem.CvssBaseScore)
					}
					if !isFixable {
						isFixable = vulnProblem.IsFixable
					}
					if len(fixedInVersions) == 0 {
						fixedInVersions = vulnProblem.InitiallyFixedInVersions
					}
					// Extract ecosystem
					if ecosystem == "" {
						if buildEco, err := vulnProblem.Ecosystem.AsSnykvulndbBuildPackageEcosystem(); err == nil {
							ecosystem = buildEco.PackageManager
						} else if osEco, err := vulnProblem.Ecosystem.AsSnykvulndbOsPackageEcosystem(); err == nil {
							ecosystem = osEco.OsName
						}
					}
					// Use package name/version from vuln problem if not set from locations
					if packageName == "" {
						packageName = vulnProblem.PackageName
					}
					if packageVersion == "" {
						packageVersion = vulnProblem.PackageVersion
					}
				}
			case "cve":
				cveProb, err := problem.AsCveProblem()
				if err == nil {
					cves = append(cves, cveProb.Id)
				}
			case "cwe":
				cweProb, err := problem.AsCweProblem()
				if err == nil {
					cwes = append(cwes, cweProb.Id)
				}
			}

			// Fallback to first problem if no snyk_vuln found
			if primaryProblem == nil && discriminator != "cve" && discriminator != "cwe" {
				primaryProblem = &problem
			}
		}
	}

	// If no ID determined from primary problem, use finding key or ID
	if id == "" && firstFinding != nil {
		if firstFinding.Attributes != nil && firstFinding.Attributes.Key != "" {
			id = firstFinding.Attributes.Key
			ruleID = firstFinding.Attributes.Key // Rule ID may be the same as key for SAST
		} else if firstFinding.Id != nil {
			id = firstFinding.Id.String()
		}
	}

	// For SCA findings, rule ID is typically the vulnerability ID
	if findingType == FindingTypeSca && id != "" {
		ruleID = id
	}

	// Deduplicate CWE and CVE lists, dependency paths, and source locations
	cwes = deduplicateStrings(cwes)
	cves = deduplicateStrings(cves)
	dependencyPaths = deduplicateStrings(dependencyPaths)
	sourceLocations = deduplicateSourceLocations(sourceLocations)

	// Build metadata map with lowercase keys for case-insensitive access
	metadata := make(map[string]interface{})
	
	// Add component information
	if packageName != "" || packageVersion != "" {
		component := map[string]string{
			"name":    packageName,
			"version": packageVersion,
		}
		metadata[strings.ToLower(MetadataKeyComponent)] = component
		metadata[strings.ToLower(MetadataKeyComponentName)] = packageName
		metadata[strings.ToLower(MetadataKeyComponentVersion)] = packageVersion
	}
	
	// Add technology/ecosystem
	if ecosystem != "" {
		metadata[strings.ToLower(MetadataKeyTechnology)] = ecosystem
	}
	
	// Add CVSS score
	if cvssScore > 0 {
		metadata[strings.ToLower(MetadataKeyCVSSScore)] = cvssScore
	}
	
	// Add fix information
	metadata[strings.ToLower(MetadataKeyIsFixable)] = isFixable
	if len(fixedInVersions) > 0 {
		metadata[strings.ToLower(MetadataKeyFixedInVersions)] = fixedInVersions
	}
	
	// Add dependency paths
	if len(dependencyPaths) > 0 {
		metadata[strings.ToLower(MetadataKeyDependencyPaths)] = dependencyPaths
	}

	return &issue{
		findings:          findings,
		findingType:       findingType,
		problems:          allProblems,
		primaryProblem:    primaryProblem,
		id:                id,
		severity:          severity,
		effectiveSeverity: effectiveSeverity,
		cwes:              cwes,
		cves:              cves,
		title:             title,
		description:       description,
		snykVulnProblem:   snykVulnProblem,
		sourceLocations:   sourceLocations,
		ruleID:            ruleID,
		riskScore:         riskScore,
		reachability:      reachability,
		metadata:          metadata,
	}, nil
}

// deduplicateStrings removes duplicate strings from a slice.
func deduplicateStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// deduplicateSourceLocations removes duplicate source locations from a slice.
// Locations are considered duplicates if they have the same file path and line number.
func deduplicateSourceLocations(slice []SourceLocation) []SourceLocation {
	seen := make(map[string]bool)
	result := make([]SourceLocation, 0, len(slice))
	for _, loc := range slice {
		key := fmt.Sprintf("%s:%d", loc.FilePath, loc.FromLine)
		if !seen[key] {
			seen[key] = true
			result = append(result, loc)
		}
	}
	return result
}

// IssueError represents an error that occurred during issue extraction or creation.
type IssueError struct {
	Message string
	Cause   error
}

func (e *IssueError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *IssueError) Unwrap() error {
	return e.Cause
}
