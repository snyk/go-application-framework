package testapi

import (
	"context"
	"fmt"
	"strings"
)

// Data keys for common issue properties (case-insensitive)
const (
	// DataKeyComponent is the key for accessing the component information (name and version)
	// Value type: map[string]string with keys "name" and "version"
	DataKeyComponent = "component"

	// DataKeyComponentName is the key for accessing just the component name
	// Value type: string
	DataKeyComponentName = "component-name"

	// DataKeyComponentVersion is the key for accessing just the component version
	// Value type: string
	DataKeyComponentVersion = "component-version"

	// DataKeyTechnology is the key for the technology/ecosystem
	// For SCA: package manager (e.g., "npm", "maven")
	// For SAST: language/framework (e.g., "javascript", "python")
	// Value type: string
	DataKeyTechnology = "technology"

	// DataKeyCVSSScore is the key for CVSS base score
	// Value type: float32
	DataKeyCVSSScore = "cvss-score"

	// DataKeyIsFixable is the key for whether a fix is available
	// Value type: bool
	DataKeyIsFixable = "is-fixable"

	// DataKeyFixedInVersions is the key for versions that fix this issue
	// Value type: []string
	DataKeyFixedInVersions = "fixed-in-versions"

	// DataKeyDependencyPaths is the key for dependency paths (SCA findings)
	// Value type: []string
	DataKeyDependencyPaths = "dependency-paths"
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

	// GetSuppression returns the suppression information for this issue.
	// Indicates if the finding is suppressed by a policy decision.
	// Returns nil if the issue is not suppressed.
	GetSuppression() *Suppression

	// GetData returns metadata value for the given key (case-insensitive).
	// Returns the value and true if found, nil and false otherwise.
	// Use the DataKey* constants for well-known keys.
	// Callers should perform type assertions on the returned interface{}.
	GetData(key string) (interface{}, bool)
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
	// Check if we have SCA findings - use ID-based grouping (by problem ID)
	for _, finding := range findings {
		if finding.Attributes != nil && finding.Attributes.FindingType == FindingTypeSca {
			return &idBasedIssueGrouper{}
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

// idBasedIssueGrouper groups findings by problem ID.
// Findings with the same problem ID are grouped together as a single issue.
// Used primarily for SCA findings where multiple findings may reference the same vulnerability.
type idBasedIssueGrouper struct{}

func (g *idBasedIssueGrouper) groupFindings(findings []FindingData) [][]FindingData {
	groups := make(map[string][]FindingData)

	for _, finding := range findings {
		if finding.Attributes == nil {
			continue
		}

		// Extract problem ID from problems
		problemID := g.extractProblemID(finding)
		if problemID == "" {
			// If no problem ID found, treat each finding as its own issue
			problemID = g.getUniqueKey(finding)
		}

		groups[problemID] = append(groups[problemID], finding)
	}

	result := make([][]FindingData, 0, len(groups))
	for _, group := range groups {
		result = append(result, group)
	}

	return result
}

func (g *idBasedIssueGrouper) extractProblemID(finding FindingData) string {
	// Extract the first available ID from any problem type for grouping
	// Works with snyk_vuln, CVE, CWE, etc. since they all have an ID field
	for _, problem := range finding.Attributes.Problems {
		if id := problem.GetID(); id != "" {
			return id
		}
	}
	return ""
}

func (g *idBasedIssueGrouper) getUniqueKey(finding FindingData) string {
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
	riskScore         uint16
	reachability      *ReachabilityEvidence
	suppression       *Suppression
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

// GetData returns metadata value for the given key (case-insensitive).
func (i *issue) GetData(key string) (interface{}, bool) {
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

// GetSuppression returns the suppression information for this issue.
func (i *issue) GetSuppression() *Suppression {
	return i.suppression
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

	builder := &issueBuilder{}
	builder.processFindings(findings)
	builder.deduplicate()
	return builder.build(), nil
}

// issueBuilder helps construct an Issue from FindingData
type issueBuilder struct {
	findingType       FindingType
	allProblems       []Problem
	primaryProblem    *Problem
	firstFinding      *FindingData
	cwes              []string
	cves              []string
	id                string
	severity          string
	effectiveSeverity string
	ecosystem         string
	title             string
	description       string
	packageName       string
	packageVersion    string
	cvssScore         float32
	isFixable         bool
	fixedInVersions   []string
	dependencyPaths   []string
	snykVulnProblem   *SnykVulnProblem
	sourceLocations   []SourceLocation
	riskScore         uint16
	reachability      *ReachabilityEvidence
	suppression       *Suppression
	findings          []FindingData
}

// processFindings extracts data from all findings
func (b *issueBuilder) processFindings(findings []FindingData) {
	b.findings = findings
	for _, finding := range findings {
		if finding.Attributes == nil {
			continue
		}
		b.processFinding(finding)
	}
	b.determineFallbackID()
}

// processFinding extracts data from a single finding
func (b *issueBuilder) processFinding(finding FindingData) {
	b.setBasicInfo(finding)
	b.allProblems = append(b.allProblems, finding.Attributes.Problems...)
	b.extractSourceLocations(finding)
	b.extractSeverityAndRisk(finding)
	b.extractEffectiveSeverity(finding)
	b.extractReachability(finding)
	b.extractSuppression(finding)
	b.extractDependencyPaths(finding)
	b.extractPackageInfo(finding)
	b.processProblems(finding)
}

// setBasicInfo sets finding type, title, and description from the first finding
func (b *issueBuilder) setBasicInfo(finding FindingData) {
	if b.findingType == "" {
		b.findingType = finding.Attributes.FindingType
		b.firstFinding = &finding
		b.title = finding.Attributes.Title
		b.description = finding.Attributes.Description
	}
}

// extractSourceLocations extracts source locations from finding locations
func (b *issueBuilder) extractSourceLocations(finding FindingData) {
	for _, location := range finding.Attributes.Locations {
		locationDiscriminator, err := location.Discriminator()
		if err != nil || locationDiscriminator != "source" {
			continue
		}
		sourceLoc, err := location.AsSourceLocation()
		if err == nil {
			b.sourceLocations = append(b.sourceLocations, sourceLoc)
		}
	}
}

// extractSeverityAndRisk extracts severity and risk score from finding attributes
func (b *issueBuilder) extractSeverityAndRisk(finding FindingData) {
	if b.severity == "" && finding.Attributes.Rating.Severity != "" {
		b.severity = string(finding.Attributes.Rating.Severity)
	}
	if finding.Attributes.Risk.RiskScore != nil && b.riskScore == 0 {
		b.riskScore = finding.Attributes.Risk.RiskScore.Value
	}
}

// extractEffectiveSeverity extracts effective severity from policy modifications
func (b *issueBuilder) extractEffectiveSeverity(finding FindingData) {
	if finding.Attributes.PolicyModifications == nil {
		return
	}
	for _, mod := range *finding.Attributes.PolicyModifications {
		if mod.Pointer == "/rating/severity" && mod.Prior != nil {
			if b.effectiveSeverity == "" && finding.Attributes.Rating.Severity != "" {
				b.effectiveSeverity = string(finding.Attributes.Rating.Severity)
			}
		}
	}
}

// extractReachability extracts reachability evidence
func (b *issueBuilder) extractReachability(finding FindingData) {
	if b.reachability != nil {
		return
	}
	for _, ev := range finding.Attributes.Evidence {
		discriminator, err := ev.Discriminator()
		if err != nil || discriminator != "reachability" {
			continue
		}
		reachEv, err := ev.AsReachabilityEvidence()
		if err == nil {
			b.reachability = &reachEv
			break
		}
	}
}

// extractSuppression extracts suppression information
func (b *issueBuilder) extractSuppression(finding FindingData) {
	if b.suppression != nil {
		return
	}
	if finding.Attributes.Suppression != nil {
		b.suppression = finding.Attributes.Suppression
	}
}

// extractDependencyPaths extracts dependency paths from evidence
func (b *issueBuilder) extractDependencyPaths(finding FindingData) {
	for _, ev := range finding.Attributes.Evidence {
		discriminator, err := ev.Discriminator()
		if err != nil || discriminator != "dependency_path" {
			continue
		}
		depPath, err := ev.AsDependencyPathEvidence()
		if err != nil {
			continue
		}
		var pathParts []string
		for _, dep := range depPath.Path {
			pathParts = append(pathParts, fmt.Sprintf("%s@%s", dep.Name, dep.Version))
		}
		if len(pathParts) > 0 {
			b.dependencyPaths = append(b.dependencyPaths, strings.Join(pathParts, " › "))
		}
	}
}

// extractPackageInfo extracts package name and version from package locations
func (b *issueBuilder) extractPackageInfo(finding FindingData) {
	for _, location := range finding.Attributes.Locations {
		locationDiscriminator, err := location.Discriminator()
		if err != nil || locationDiscriminator != "package" {
			continue
		}
		pkgLoc, err := location.AsPackageLocation()
		if err != nil {
			continue
		}
		if b.packageName == "" {
			b.packageName = pkgLoc.Package.Name
		}
		if b.packageVersion == "" {
			b.packageVersion = pkgLoc.Package.Version
		}
	}
}

// processProblems processes all problems to extract CVEs, CWEs, and vulnerability info
func (b *issueBuilder) processProblems(finding FindingData) {
	for _, problem := range finding.Attributes.Problems {
		discriminator, err := problem.Discriminator()
		if err != nil {
			continue
		}

		switch discriminator {
		case "snyk_vuln":
			b.processSnykVulnProblem(problem)
		case "cve":
			b.processCveProblem(problem)
		case "cwe":
			b.processCweProblem(problem)
		}

		// Fallback to first problem if no snyk_vuln found
		if b.primaryProblem == nil && discriminator != "cve" && discriminator != "cwe" {
			b.primaryProblem = &problem
		}
	}
}

// processSnykVulnProblem extracts data from a Snyk vulnerability problem
func (b *issueBuilder) processSnykVulnProblem(problem Problem) {
	// Quick ID extraction without full unmarshal
	if id := problem.GetID(); id != "" {
		b.id = id
	}

	// Full unmarshal for detailed metadata
	vulnProblem, err := problem.AsSnykVulnProblem()
	if err != nil {
		return
	}

	if b.primaryProblem == nil {
		b.primaryProblem = &problem
		b.snykVulnProblem = &vulnProblem
	}

	// Set severity and other metadata from first vuln problem
	if b.severity == "" {
		b.severity = string(vulnProblem.Severity)
	}
	if b.cvssScore == 0.0 {
		b.cvssScore = float32(vulnProblem.CvssBaseScore)
	}
	if !b.isFixable {
		b.isFixable = vulnProblem.IsFixable
	}
	if len(b.fixedInVersions) == 0 {
		b.fixedInVersions = vulnProblem.InitiallyFixedInVersions
	}

	// Extract ecosystem
	if b.ecosystem == "" {
		if buildEco, err := vulnProblem.Ecosystem.AsSnykvulndbBuildPackageEcosystem(); err == nil {
			b.ecosystem = buildEco.PackageManager
		} else if osEco, err := vulnProblem.Ecosystem.AsSnykvulndbOsPackageEcosystem(); err == nil {
			b.ecosystem = osEco.OsName
		}
	}

	// Use package name/version from vuln problem if not set from locations
	if b.packageName == "" {
		b.packageName = vulnProblem.PackageName
	}
	if b.packageVersion == "" {
		b.packageVersion = vulnProblem.PackageVersion
	}
}

// processCveProblem extracts CVE ID
func (b *issueBuilder) processCveProblem(problem Problem) {
	if id := problem.GetID(); id != "" {
		b.cves = append(b.cves, id)
	}
}

// processCweProblem extracts CWE ID
func (b *issueBuilder) processCweProblem(problem Problem) {
	if id := problem.GetID(); id != "" {
		b.cwes = append(b.cwes, id)
	}
}

// determineFallbackID sets ID from finding key or ID if not already set
func (b *issueBuilder) determineFallbackID() {
	if b.id == "" && b.firstFinding != nil {
		if b.firstFinding.Attributes != nil && b.firstFinding.Attributes.Key != "" {
			b.id = b.firstFinding.Attributes.Key
		} else if b.firstFinding.Id != nil {
			b.id = b.firstFinding.Id.String()
		}
	}
}

// deduplicate removes duplicate values from collected data
func (b *issueBuilder) deduplicate() {
	b.cwes = deduplicateStrings(b.cwes)
	b.cves = deduplicateStrings(b.cves)
	b.dependencyPaths = deduplicateStrings(b.dependencyPaths)
	b.sourceLocations = deduplicateSourceLocations(b.sourceLocations)
}

// build constructs the final Issue from collected data
func (b *issueBuilder) build() *issue {
	metadata := b.buildMetadata()

	return &issue{
		findings:          b.findings,
		findingType:       b.findingType,
		problems:          b.allProblems,
		primaryProblem:    b.primaryProblem,
		id:                b.id,
		severity:          b.severity,
		effectiveSeverity: b.effectiveSeverity,
		cwes:              b.cwes,
		cves:              b.cves,
		title:             b.title,
		description:       b.description,
		snykVulnProblem:   b.snykVulnProblem,
		sourceLocations:   b.sourceLocations,
		riskScore:         b.riskScore,
		reachability:      b.reachability,
		suppression:       b.suppression,
		metadata:          metadata,
	}
}

// buildMetadata constructs the metadata map
func (b *issueBuilder) buildMetadata() map[string]interface{} {
	metadata := make(map[string]interface{})

	// Add component information
	if b.packageName != "" || b.packageVersion != "" {
		component := map[string]string{
			"name":    b.packageName,
			"version": b.packageVersion,
		}
		metadata[DataKeyComponent] = component
		metadata[DataKeyComponentName] = b.packageName
		metadata[DataKeyComponentVersion] = b.packageVersion
	}

	// Add technology/ecosystem
	if b.ecosystem != "" {
		metadata[DataKeyTechnology] = b.ecosystem
	}

	// Add CVSS score
	if b.cvssScore > 0 {
		metadata[DataKeyCVSSScore] = b.cvssScore
	}

	// Add fix information
	metadata[DataKeyIsFixable] = b.isFixable
	if len(b.fixedInVersions) > 0 {
		metadata[DataKeyFixedInVersions] = b.fixedInVersions
	}

	// Add dependency paths
	if len(b.dependencyPaths) > 0 {
		metadata[DataKeyDependencyPaths] = b.dependencyPaths
	}

	return metadata
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
