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
			// Extract CVE and CWE IDs from all problems
			cveIds, cweIds, vulnProblemPtr := extractProblemsData(finding.Attributes.Problems)

			if vulnProblemPtr == nil {
				continue
			}
			vulnProblem := *vulnProblemPtr

			if _, ok := sarifRules[vulnProblem.Id]; !ok {
				// Build shortDescription
				shortDesc := fmt.Sprintf("%s severity - %s vulnerability in %s",
					cases.Title(language.English).String(string(vulnProblem.Severity)),
					finding.Attributes.Title,
					vulnProblem.PackageName)

				// Build fullDescription with CVE IDs
				fullDesc := fmt.Sprintf("%s@%s", vulnProblem.PackageName, vulnProblem.PackageVersion)
				if len(cveIds) > 0 {
					fullDesc = fmt.Sprintf("(%s) %s", strings.Join(cveIds, ", "), fullDesc)
				}

				// Build dependency paths from evidence
				depPaths := buildDependencyPaths(finding.Attributes.Evidence)

				// Build help markdown with package manager, vulnerable module, and detailed paths
				helpMarkdown := buildHelpMarkdown(vulnProblem, depPaths, finding.Attributes.Description)

				// Build properties with tags including CWEs
				tags := []interface{}{"security"}
				for _, cwe := range cweIds {
					tags = append(tags, cwe)
				}
				// Add ecosystem if available
				if ecosystemName := getEcosystemName(vulnProblem.Ecosystem); ecosystemName != "" {
					tags = append(tags, ecosystemName)
				}

				properties := map[string]interface{}{
					"cvssv3_baseScore":  vulnProblem.CvssBaseScore,
					"security-severity": fmt.Sprintf("%.1f", vulnProblem.CvssBaseScore),
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

// GetResultsFromTestResult extracts SARIF results from test results for a specific finding type.
// Groups findings by vulnerability ID to match TypeScript CLI behavior.
func GetResultsFromTestResult(result testapi.TestResult, t testapi.FindingType) []map[string]interface{} {
	findings, _, err := result.Findings(context.Background())
	if err != nil {
		return []map[string]interface{}{}
	}

	// Handle SCA findings - group by vulnerability ID
	if t == testapi.FindingTypeSca {
		return getScaResults(findings)
	}
	// TODO: Add SAST handling here later
	// else if t == testapi.FindingTypeSast { return getSastResults(findings) }

	return []map[string]interface{}{}
}

// getScaResults groups SCA findings by vulnerability ID and creates SARIF results
func getScaResults(findings []testapi.FindingData) []map[string]interface{} {
	// Group findings by vulnerability ID
	vulnMap := make(map[string][]testapi.FindingData)
	vulnProblems := make(map[string]testapi.SnykVulnProblem)

	for _, finding := range findings {
		if finding.Attributes.FindingType != testapi.FindingTypeSca {
			continue
		}

		for _, problem := range finding.Attributes.Problems {
			if discriminator, err := problem.Discriminator(); err == nil && discriminator != "snyk_vuln" {
				continue
			}

			vulnProblem, err := problem.AsSnykVulnProblem()
			if err != nil {
				continue
			}

			vulnMap[vulnProblem.Id] = append(vulnMap[vulnProblem.Id], finding)
			if _, exists := vulnProblems[vulnProblem.Id]; !exists {
				vulnProblems[vulnProblem.Id] = vulnProblem
			}
		}
	}

	// Create SARIF results from grouped findings
	var results []map[string]interface{}
	for vulnId, groupedFindings := range vulnMap {
		vulnProblem := vulnProblems[vulnId]

		// Use the first finding for location information
		firstFinding := groupedFindings[0]

		// Build message
		message := map[string]interface{}{
			"text": fmt.Sprintf("This file introduces a vulnerable %s package with a %s severity vulnerability.",
				vulnProblem.PackageName,
				vulnProblem.Severity),
		}

		// Build location
		location := buildScaLocation(firstFinding, vulnProblem)

		// Build result
		sarifResult := map[string]interface{}{
			"ruleId":    vulnProblem.Id,
			"level":     SeverityToSarifLevel(string(vulnProblem.Severity)),
			"message":   message,
			"locations": []interface{}{location},
		}

		// Add fixes if available
		if vulnProblem.IsFixable && len(vulnProblem.InitiallyFixedInVersions) > 0 {
			fixes := buildScaFixes(firstFinding, vulnProblem)
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

// extractProblemsData extracts CVE IDs, CWE IDs, and the vulnerability problem from a finding's problems
func extractProblemsData(problems []testapi.Problem) ([]string, []string, *testapi.SnykVulnProblem) {
	var cveIds []string
	var cweIds []string
	var vulnProblem *testapi.SnykVulnProblem

	for _, problem := range problems {
		discriminator, err := problem.Discriminator()
		if err != nil {
			continue
		}

		switch discriminator {
		case "snyk_vuln":
			if vulnProblem == nil {
				if vp, err := problem.AsSnykVulnProblem(); err == nil {
					vulnProblem = &vp
				}
			}
		case "cve":
			if cveProb, err := problem.AsCveProblem(); err == nil {
				cveIds = append(cveIds, cveProb.Id)
			}
		case "cwe":
			if cweProb, err := problem.AsCweProblem(); err == nil {
				cweIds = append(cweIds, cweProb.Id)
			}
		}
	}

	return cveIds, cweIds, vulnProblem
}

// getEcosystemName extracts the ecosystem name (e.g., "npm") from the package ecosystem
func getEcosystemName(ecosystem testapi.SnykvulndbPackageEcosystem) string {
	// Try as build ecosystem first
	if buildEco, err := ecosystem.AsSnykvulndbBuildPackageEcosystem(); err == nil {
		return buildEco.PackageManager
	}
	// Try as OS ecosystem
	if osEco, err := ecosystem.AsSnykvulndbOsPackageEcosystem(); err == nil {
		return osEco.OsName
	}
	// Fallback to empty string
	return ""
}

// buildDependencyPaths extracts dependency paths from finding evidence
func buildDependencyPaths(evidence []testapi.Evidence) []string {
	var paths []string

	for _, ev := range evidence {
		if discriminator, err := ev.Discriminator(); err == nil && discriminator == "dependency_path" {
			if depPath, err := ev.AsDependencyPathEvidence(); err == nil {
				var pathParts []string
				for _, dep := range depPath.Path {
					pathParts = append(pathParts, fmt.Sprintf("%s@%s", dep.Name, dep.Version))
				}
				if len(pathParts) > 0 {
					paths = append(paths, strings.Join(pathParts, " › "))
				}
			}
		}
	}

	return paths
}

// buildHelpMarkdown constructs the help markdown section for SARIF rules
func buildHelpMarkdown(vulnProblem testapi.SnykVulnProblem, depPaths []string, description string) string {
	var sb strings.Builder

	// Package Manager
	ecosystemName := getEcosystemName(vulnProblem.Ecosystem)
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
