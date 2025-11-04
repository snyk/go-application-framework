package testapi

import (
	"context"
	"fmt"
	"strings"
)

//go:generate go run github.com/golang/mock/mockgen -source=issues.go -destination=../mocks/issues.go -package=mocks

// Issue defines the interface for accessing a single aggregated security issue.
// An issue represents a cohesive security problem derived from one or more related findings.
// This interface is designed to be easily convertible to snyk-ls Issue format.
type Issue interface {
	// GetFindings returns all findings that are part of this issue.
	GetFindings() []FindingData

	// GetFindingType returns the finding type of this issue.
	// All findings in an issue should have the same finding type.
	GetFindingType() FindingType

	// GetProblems returns all problems from all findings in this issue.
	GetProblems() []Problem

	// GetPrimaryProblem returns the primary problem for this issue.
	// For SCA findings, this would be the SnykVulnProblem.
	// Returns nil if no primary problem can be determined.
	GetPrimaryProblem() *Problem

	// GetID returns the unique identifier for this issue.
	// For SCA findings, this is typically the vulnerability ID.
	// For other finding types, this may be derived from the finding key or rule ID.
	GetID() string

	// GetSeverity returns the severity of this issue.
	// Returns empty string if severity cannot be determined.
	GetSeverity() string

	// GetEcosystem returns the package ecosystem/manager for this issue.
	// Returns empty string if not applicable (e.g., for SAST findings).
	GetEcosystem() string

	// GetCWEs returns the CWE identifiers associated with this issue.
	GetCWEs() []string

	// GetCVEs returns the CVE identifiers associated with this issue.
	GetCVEs() []string

	// GetTitle returns the title of this issue.
	// Typically comes from the first finding's title attribute.
	GetTitle() string

	// GetDescription returns the description of this issue.
	// Typically comes from the first finding's description attribute.
	GetDescription() string

	// GetSnykVulnProblem returns the SnykVulnProblem if this is an SCA issue.
	// Returns nil and an error if this is not an SCA issue or no vulnerability problem exists.
	GetSnykVulnProblem() (*SnykVulnProblem, error)

	// GetPackageName returns the package name for this issue.
	// For SCA findings, this comes from the vulnerability problem or package location.
	// Returns empty string if not applicable.
	GetPackageName() string

	// GetPackageVersion returns the package version for this issue.
	// For SCA findings, this comes from the vulnerability problem or package location.
	// Returns empty string if not applicable.
	GetPackageVersion() string

	// GetCvssScore returns the CVSS base score for this issue.
	// Returns 0.0 if not available.
	GetCvssScore() float32

	// GetIsFixable returns whether this issue has a fix available.
	GetIsFixable() bool

	// GetFixedInVersions returns the list of versions that fix this issue.
	GetFixedInVersions() []string

	// GetDependencyPaths returns the dependency paths that introduce this issue.
	// Each path is a string representation of the dependency chain.
	GetDependencyPaths() []string
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
	ecosystem         string
	cwes              []string
	cves              []string
	title             string
	description       string
	packageName       string
	packageVersion    string
	cvssScore         float32
	isFixable         bool
	fixedInVersions   []string
	dependencyPaths   []string
	snykVulnProblem   *SnykVulnProblem
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

// GetEcosystem returns the package ecosystem/manager for this issue.
func (i *issue) GetEcosystem() string {
	return i.ecosystem
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

// GetSnykVulnProblem returns the SnykVulnProblem if this is an SCA issue.
func (i *issue) GetSnykVulnProblem() (*SnykVulnProblem, error) {
	if i.snykVulnProblem == nil {
		return nil, fmt.Errorf("no SnykVulnProblem available for this issue")
	}
	return i.snykVulnProblem, nil
}

// GetPackageName returns the package name for this issue.
func (i *issue) GetPackageName() string {
	return i.packageName
}

// GetPackageVersion returns the package version for this issue.
func (i *issue) GetPackageVersion() string {
	return i.packageVersion
}

// GetCvssScore returns the CVSS base score for this issue.
func (i *issue) GetCvssScore() float32 {
	return i.cvssScore
}

// GetIsFixable returns whether this issue has a fix available.
func (i *issue) GetIsFixable() bool {
	return i.isFixable
}

// GetFixedInVersions returns the list of versions that fix this issue.
func (i *issue) GetFixedInVersions() []string {
	return i.fixedInVersions
}

// GetDependencyPaths returns the dependency paths that introduce this issue.
func (i *issue) GetDependencyPaths() []string {
	return i.dependencyPaths
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
				if primaryProblem == nil {
					vulnProblem, err := problem.AsSnykVulnProblem()
					if err == nil {
						primaryProblem = &problem
						snykVulnProblem = &vulnProblem
						id = vulnProblem.Id
						severity = string(vulnProblem.Severity)
						cvssScore = float32(vulnProblem.CvssBaseScore)
						isFixable = vulnProblem.IsFixable
						fixedInVersions = vulnProblem.InitiallyFixedInVersions
						// Extract ecosystem
						if buildEco, err := vulnProblem.Ecosystem.AsSnykvulndbBuildPackageEcosystem(); err == nil {
							ecosystem = buildEco.PackageManager
						} else if osEco, err := vulnProblem.Ecosystem.AsSnykvulndbOsPackageEcosystem(); err == nil {
							ecosystem = osEco.OsName
						}
						// Use package name/version from vuln problem if not set from locations
						if packageName == "" {
							packageName = vulnProblem.PackageName
						}
						if packageVersion == "" {
							packageVersion = vulnProblem.PackageVersion
						}
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
		} else if firstFinding.Id != nil {
			id = firstFinding.Id.String()
		}
	}

	// Deduplicate CWE and CVE lists and dependency paths
	cwes = deduplicateStrings(cwes)
	cves = deduplicateStrings(cves)
	dependencyPaths = deduplicateStrings(dependencyPaths)

	return &issue{
		findings:          findings,
		findingType:       findingType,
		problems:          allProblems,
		primaryProblem:    primaryProblem,
		id:                id,
		severity:          severity,
		ecosystem:         ecosystem,
		cwes:              cwes,
		cves:              cves,
		title:             title,
		description:       description,
		packageName:       packageName,
		packageVersion:    packageVersion,
		cvssScore:         cvssScore,
		isFixable:         isFixable,
		fixedInVersions:   fixedInVersions,
		dependencyPaths:   dependencyPaths,
		snykVulnProblem:   snykVulnProblem,
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
