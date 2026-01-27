package ufm_helpers

import (
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"golang.org/x/mod/semver"
)

type RemediationSummary struct {
	Upgrades   []*UpgradeGroup
	Pins       []*PinGroup
	Unresolved []testapi.Issue
}

func (s *RemediationSummary) HasUpgrades() bool {
	return len(s.Upgrades) > 0
}

func (s *RemediationSummary) HasPins() bool {
	return len(s.Pins) > 0
}

func (s *RemediationSummary) HasUnresolved() bool {
	return len(s.Unresolved) > 0
}

type UpgradeGroup struct {
	FromPackage testapi.Package
	ToPackage   testapi.Package
	FixedIssues []testapi.Issue
}

type PinGroup struct {
	FromPackage testapi.Package
	ToPackage   testapi.Package
	FixedIssues []testapi.Issue
}

func GetRemediationSummary(issues []testapi.Issue) *RemediationSummary {
	summary := &RemediationSummary{
		Upgrades:   []*UpgradeGroup{},
		Pins:       []*PinGroup{},
		Unresolved: []testapi.Issue{},
	}

	upgradeMap := make(map[string]*UpgradeGroup)
	pinMap := make(map[string][]*PinGroup)

	for _, issue := range issues {
		if ignoreDetails := issue.GetIgnoreDetails(); ignoreDetails != nil && ignoreDetails.IsActive() {
			continue
		}

		fixAttrs := getFixAttributes(issue)
		if fixAttrs == nil {
			continue
		}

		if fixAttrs.Outcome == testapi.Unresolved {
			summary.Unresolved = append(summary.Unresolved, issue)
			continue
		}

		if fixAttrs.Action == nil {
			continue
		}

		action, err := fixAttrs.Action.ValueByDiscriminator()
		if err != nil {
			continue
		}

		switch advice := action.(type) {
		case testapi.UpgradePackageAdvice:
			if !processUpgradeAdvice(issue, advice, fixAttrs.Outcome, upgradeMap) {
				summary.Unresolved = append(summary.Unresolved, issue)
			}
		case testapi.PinPackageAdvice:
			processPinAdvice(issue, advice, pinMap)
		}
	}

	for _, upgrade := range upgradeMap {
		summary.Upgrades = append(summary.Upgrades, upgrade)
	}
	for _, pins := range pinMap {
		summary.Pins = append(summary.Pins, pins...)
	}

	return summary
}

func getFixAttributes(issue testapi.Issue) *testapi.FixAttributes {
	for _, finding := range issue.GetFindings() {
		if finding.Relationships != nil &&
			finding.Relationships.Fix != nil &&
			finding.Relationships.Fix.Data != nil &&
			finding.Relationships.Fix.Data.Attributes != nil {
			return finding.Relationships.Fix.Data.Attributes
		}
	}
	return nil
}

func processUpgradeAdvice(issue testapi.Issue, advice testapi.UpgradePackageAdvice, outcome testapi.FixAppliedOutcome, upgradeMap map[string]*UpgradeGroup) bool {
	if len(advice.UpgradePaths) == 0 {
		return false
	}

	depPaths, ok := issue.GetData(testapi.DataKeyDependencyPaths)
	if !ok || depPaths == nil {
		return false
	}

	paths, ok := depPaths.([][]testapi.Package)
	if !ok || len(paths) == 0 {
		return false
	}

	matchedPaths := 0

	for _, upgradePath := range advice.UpgradePaths {
		if len(upgradePath.DependencyPath) < 2 {
			continue
		}

		for _, depPath := range paths {
			if len(depPath) < 2 || !pathsMatch(upgradePath.DependencyPath, depPath) {
				continue
			}

			matchedPaths++
			fromPkg := depPath[1]
			toPkg := upgradePath.DependencyPath[1]
			key := fmt.Sprintf("%s@%s", fromPkg.Name, fromPkg.Version)

			addOrUpdateUpgradeGroup(upgradeMap, key, fromPkg, toPkg, issue)
			break
		}
	}

	hasUnmatchedPaths := matchedPaths < len(paths)
	return outcome == testapi.FullyResolved || !hasUnmatchedPaths
}

func addOrUpdateUpgradeGroup(upgradeMap map[string]*UpgradeGroup, key string, fromPkg, toPkg testapi.Package, issue testapi.Issue) {
	if existing, exists := upgradeMap[key]; exists {
		if !containsIssue(existing.FixedIssues, issue) {
			existing.FixedIssues = append(existing.FixedIssues, issue)
		}
		if compareVersions(toPkg.Version, existing.ToPackage.Version) > 0 {
			existing.ToPackage.Version = toPkg.Version
		}
	} else {
		upgradeMap[key] = &UpgradeGroup{
			FromPackage: fromPkg,
			ToPackage:   toPkg,
			FixedIssues: []testapi.Issue{issue},
		}
	}
}

func processPinAdvice(issue testapi.Issue, advice testapi.PinPackageAdvice, pinMap map[string][]*PinGroup) {
	vulnerablePkg := getVulnerablePackage(issue)
	key := vulnerablePkg.Name
	toPkg := testapi.Package{Name: advice.PackageName, Version: advice.PinVersion}

	existingPins, exists := pinMap[key]
	if exists {
		for _, pin := range existingPins {
			if compareVersions(toPkg.Version, pin.ToPackage.Version) > 0 {
				pin.ToPackage.Version = toPkg.Version
			}
		}

		versionFound := false
		for _, pin := range existingPins {
			if pin.FromPackage.Version == vulnerablePkg.Version {
				if !containsIssue(pin.FixedIssues, issue) {
					pin.FixedIssues = append(pin.FixedIssues, issue)
				}
				versionFound = true
				break
			}
		}

		if !versionFound {
			highestToVersion := toPkg.Version
			for _, pin := range existingPins {
				if compareVersions(pin.ToPackage.Version, highestToVersion) > 0 {
					highestToVersion = pin.ToPackage.Version
				}
			}
			pinMap[key] = append(existingPins, &PinGroup{
				FromPackage: vulnerablePkg,
				ToPackage:   testapi.Package{Name: toPkg.Name, Version: highestToVersion},
				FixedIssues: []testapi.Issue{issue},
			})
		}
	} else {
		pinMap[key] = []*PinGroup{{
			FromPackage: vulnerablePkg,
			ToPackage:   toPkg,
			FixedIssues: []testapi.Issue{issue},
		}}
	}
}

func getVulnerablePackage(issue testapi.Issue) testapi.Package {
	if componentName, ok := issue.GetData(testapi.DataKeyComponentName); ok {
		if name, ok := componentName.(string); ok {
			version := ""
			if componentVersion, ok := issue.GetData(testapi.DataKeyComponentVersion); ok {
				if v, ok := componentVersion.(string); ok {
					version = v
				}
			}
			return testapi.Package{Name: name, Version: version}
		}
	}

	findings := issue.GetFindings()
	if len(findings) > 0 && findings[0].Attributes != nil {
		for _, loc := range findings[0].Attributes.Locations {
			disc, err := loc.Discriminator()
			if err != nil || disc != "package" {
				continue
			}
			pkgLoc, err := loc.AsPackageLocation()
			if err == nil {
				return pkgLoc.Package
			}
		}
	}

	return testapi.Package{}
}

func pathsMatch(upgradePath, depPath []testapi.Package) bool {
	if len(upgradePath) > len(depPath) {
		return false
	}
	for i, pkg := range upgradePath {
		if pkg.Name != depPath[i].Name {
			return false
		}
	}
	return true
}

func containsIssue(issues []testapi.Issue, issue testapi.Issue) bool {
	issueID := issue.GetID()
	issueVersion, _ := issue.GetData(testapi.DataKeyComponentVersion)

	for _, existing := range issues {
		if existing.GetID() != issueID {
			continue
		}
		existingVersion, _ := existing.GetData(testapi.DataKeyComponentVersion)
		if issueVersion == existingVersion {
			return true
		}
	}
	return false
}

func compareVersions(v1, v2 string) int {
	if !strings.HasPrefix(v1, "v") {
		v1 = "v" + v1
	}
	if !strings.HasPrefix(v2, "v") {
		v2 = "v" + v2
	}
	return semver.Compare(v1, v2)
}
