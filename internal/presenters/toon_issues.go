package presenters

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/snyk/go-application-framework/internal/ufm_helpers"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

type toonIssueRows struct {
	Section string
	Rows    []any
}

func mapTOONIssue(issue testapi.Issue, full bool) (toonIssueRows, error) {
	switch issue.GetFindingType() {
	case testapi.FindingTypeSca, testapi.FindingTypeLicense:
		row, err := mapTOONSCAIssue(issue, full)
		return toonIssueRows{Section: "sca", Rows: []any{row}}, err
	case testapi.FindingTypeSecret, testapi.FindingTypeSecrets:
		return toonIssueRows{Section: "secrets", Rows: mapTOONSecretIssue(issue)}, nil
	default:
		return toonIssueRows{Section: "findings", Rows: []any{mapTOONFinding(issue)}}, nil
	}
}

func mapTOONFinding(issue testapi.Issue) map[string]any {
	return map[string]any{
		"id":           issue.GetID(),
		"finding_type": string(issue.GetFindingType()),
		"title":        issue.GetTitle(),
		"severity":     issue.GetEffectiveSeverity(),
	}
}

func mapTOONSecretIssue(issue testapi.Issue) []any {
	rows := make([]any, 0, len(issue.GetFindings()))
	for _, finding := range issue.GetFindings() {
		if finding.Attributes == nil {
			continue
		}
		attributes := finding.Attributes
		rule := issue.GetProblemID()
		if rule == "" {
			rule = attributes.Title
		}
		if rule == "" {
			rule = "secret"
		}
		file := "unknown"
		line := 0
		if len(attributes.Locations) > 0 {
			if location, err := attributes.Locations[0].AsSourceLocation(); err == nil {
				if location.FilePath != "" {
					file = location.FilePath
				}
				line = location.FromLine
			}
		}
		severity := strings.ToLower(string(attributes.Rating.Severity))
		if severity == "" {
			severity = "low"
		}
		rows = append(rows, map[string]any{
			"rule": rule, "severity": severity, "file": file,
			"line": json.Number(strconv.Itoa(line)),
		})
	}
	return rows
}

func mapTOONSCAIssue(issue testapi.Issue, full bool) (map[string]any, error) {
	problem := issue.GetPrimaryProblem()
	if problem == nil {
		return nil, fmt.Errorf("SCA finding has no supported problem")
	}
	discriminator, err := problem.Discriminator()
	if err != nil || (discriminator != "snyk_vuln" && discriminator != "snyk_license") {
		return nil, fmt.Errorf("SCA finding has no supported problem")
	}
	fields, err := jsonFields[string](problem, "id", "severity")
	if err != nil {
		return nil, err
	}
	name, _ := issueData[string](issue, testapi.DataKeyComponentName)
	versions, _ := issueData[[]string](issue, "component-versions")
	versions = slices.Clone(versions)
	slices.Sort(versions)
	findings := issue.GetFindings()
	if len(findings) == 1 {
		name, versions, err = singleFindingComponent(findings[0], problem, name)
		if err != nil {
			return nil, err
		}
	}
	fixable, upgrade := toonRemediation(issue)
	row := map[string]any{
		"id": fields["id"], "severity": fields["severity"],
		"pkg": name + "@" + strings.Join(versions, ","), "fixable": fixable,
	}
	if full {
		if err := validateTOONCVSS(issue); err != nil {
			return nil, err
		}
		scores, err := jsonFields[float64](problem, "cvss_base_score")
		if err != nil {
			return nil, err
		}
		cvss := "n/a"
		if score, ok := scores["cvss_base_score"]; ok {
			cvss = fmt.Sprintf("%.1f", score)
		}
		row["title"] = truncateTOONTitle(issue.GetTitle())
		row["cvss"] = cvss
		row["upgrade"] = upgrade
	}
	return row, nil
}

func toonRemediation(issue testapi.Issue) (fixable, target string) {
	fixable, target = "no", "none"
	attributes := ufm_helpers.GetFixAttributes(issue)
	if attributes == nil || attributes.Action == nil {
		return
	}
	if advice, err := attributes.Action.AsUpgradePackageAdvice(); err == nil {
		for _, path := range advice.UpgradePaths {
			if len(path.DependencyPath) >= 2 {
				fixable = "yes"
				break
			}
		}
	}
	name, version := ufm_helpers.GetDirectPackageUpgradeTarget(attributes)
	if name == "" || version == "" {
		name, version = ufm_helpers.GetDirectPackagePinTarget(attributes)
	}
	if name != "" && version != "" {
		return "yes", name + "@" + version
	}
	return
}

func singleFindingComponent(finding *testapi.FindingData, problem *testapi.Problem, fallbackName string) (string, []string, error) {
	fields, err := jsonFields[string](problem, "package_name", "package_version")
	if err != nil {
		return "", nil, err
	}
	name := fields["package_name"]
	if name == "" {
		name = fallbackName
	}
	version := fields["package_version"]
	if finding.Attributes != nil {
		for _, location := range finding.Attributes.Locations {
			discriminator, err := location.Discriminator()
			if err != nil {
				return "", nil, err
			}
			if discriminator != "package" {
				continue
			}
			pkg, err := location.AsPackageLocation()
			if err != nil {
				return "", nil, err
			}
			if pkg.Package.Name != "" {
				name = pkg.Package.Name
			}
			if pkg.Package.Version != "" {
				version = pkg.Package.Version
			}
			break
		}
	}
	if version == "" {
		return name, []string{}, nil
	}
	return name, []string{version}, nil
}

func validateTOONCVSS(issue testapi.Issue) error {
	for _, problem := range issue.GetProblems() {
		discriminator, err := problem.Discriminator()
		if err != nil {
			return err
		}
		if discriminator == "snyk_vuln" {
			if _, err := jsonFields[float64](problem, "cvss_base_score"); err != nil {
				return err
			}
		}
	}
	return nil
}

func truncateTOONTitle(title string) string {
	runes := []rune(title)
	if len(runes) <= 80 {
		return title
	}
	return fmt.Sprintf("%s…(+%d chars)", string(runes[:80]), len(runes)-80)
}

func issueData[T any](issue testapi.Issue, key string) (T, bool) {
	value, ok := issue.GetData(key)
	if !ok {
		var zero T
		return zero, false
	}
	typed, ok := value.(T)
	return typed, ok
}
