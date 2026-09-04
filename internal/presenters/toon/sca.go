package toon

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

var scaSeverityOrder = []string{"critical", "high", "medium", "low"}

// ProjectSCA maps native UFM SCA findings to the concise TOON view model.
func ProjectSCA(results []testapi.TestResult) (SCAView, error) {
	issues, err := issuesByFindingType(results, testapi.FindingTypeSca)
	if err != nil {
		return SCAView{}, err
	}

	aggregated := aggregateSCAIssues(issues)
	if len(aggregated) == 0 {
		return SCAView{Summary: "0 vulnerabilities found"}, nil
	}

	totalPaths := 0
	counts := map[string]int{}
	fixableCount := 0
	rows := make([]SCARow, 0, len(aggregated))

	for _, agg := range aggregated {
		totalPaths += agg.pathCount
		severity := strings.ToLower(agg.severity)
		counts[severity]++
		if agg.fixable {
			fixableCount++
		}
		rows = append(rows, SCARow{
			ID:       agg.id,
			Severity: severity,
			Pkg:      formatPkg(agg.name, agg.versions),
			Fixable:  yesNo(agg.fixable),
		})
	}

	return SCAView{
		Rows:    rows,
		Summary: scaSummary(len(rows), totalPaths, fixableCount, counts),
	}, nil
}

type scaAggregate struct {
	id        string
	severity  string
	name      string
	versions  []string
	fixable   bool
	pathCount int
}

func aggregateSCAIssues(issues []testapi.Issue) []scaAggregate {
	byID := map[string]*scaAggregate{}
	order := make([]string, 0, len(issues))

	for _, issue := range issues {
		id := issue.GetID()
		agg := byID[id]
		if agg == nil {
			agg = &scaAggregate{
				id:       id,
				severity: issue.GetSeverity(),
				fixable:  isIssueFixable(issue),
			}
			byID[id] = agg
			order = append(order, id)
		}

		agg.pathCount += len(issue.GetFindings())
		agg.fixable = agg.fixable || isIssueFixable(issue)
		if agg.severity == "" {
			agg.severity = issue.GetSeverity()
		}

		name, versions := packageVersionsFromIssue(issue)
		if agg.name == "" && name != "" {
			agg.name = name
		}
		agg.versions = mergeSortedVersions(agg.versions, versions)
	}

	out := make([]scaAggregate, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

func isIssueFixable(issue testapi.Issue) bool {
	if val, ok := issue.GetData(testapi.DataKeyIsFixable); ok {
		if fixable, ok := val.(bool); ok {
			return fixable
		}
	}
	return false
}

func packageVersionsFromIssue(issue testapi.Issue) (string, []string) {
	seen := map[string]bool{}
	var name string
	var versions []string

	for _, finding := range issue.GetFindings() {
		pkgName, version := packageFromFinding(finding)
		if pkgName != "" && name == "" {
			name = pkgName
		}
		if version != "" && !seen[version] {
			seen[version] = true
			versions = append(versions, version)
		}
	}

	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i], versions[j]) < 0
	})
	return name, versions
}

func packageFromFinding(finding *testapi.FindingData) (string, string) {
	if finding == nil || finding.Attributes == nil {
		return "", ""
	}
	for _, location := range finding.Attributes.Locations {
		pkgLoc, err := location.AsPackageLocation()
		if err != nil {
			continue
		}
		return pkgLoc.Package.Name, pkgLoc.Package.Version
	}
	return "", ""
}

func mergeSortedVersions(existing, additional []string) []string {
	seen := map[string]bool{}
	for _, v := range existing {
		seen[v] = true
	}
	merged := append([]string{}, existing...)
	for _, v := range additional {
		if v != "" && !seen[v] {
			seen[v] = true
			merged = append(merged, v)
		}
	}
	sort.Slice(merged, func(i, j int) bool {
		return compareVersions(merged[i], merged[j]) < 0
	})
	return merged
}

func formatPkg(name string, versions []string) string {
	if name == "" {
		return ""
	}
	if len(versions) == 0 {
		return name
	}
	return fmt.Sprintf("%s@%s", name, strings.Join(versions, ","))
}

func scaSummary(uniqueCount, totalPaths, fixable int, counts map[string]int) string {
	if uniqueCount == 0 {
		return "0 vulnerabilities found"
	}

	var parts []string
	for _, severity := range scaSeverityOrder {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], severity))
		}
	}

	pathSuffix := ""
	if totalPaths > uniqueCount {
		pathSuffix = fmt.Sprintf(" (%d paths)", totalPaths)
	}

	return fmt.Sprintf("%d unique vulns%s | %s | %d fixable",
		uniqueCount, pathSuffix, strings.Join(parts, " "), fixable)
}

func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aErr := strconv.Atoi(as[i])
		bn, bErr := strconv.Atoi(bs[i])
		if aErr == nil && bErr == nil {
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
			continue
		}
		if as[i] != bs[i] {
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	return len(as) - len(bs)
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
