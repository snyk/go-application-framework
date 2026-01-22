package testapi

import (
	"fmt"
	"strings"
)

type RemediationSummary struct {
	Upgrades   []*UpgradeGroup
	Pins       []*PinGroup
	Unresolved []Issue
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
	FromPackage Package
	ToPackage   Package
	Fixes       []Issue
}

type PinGroup struct {
	FromPackage Package
	ToPackage   Package
	Fixes       []Issue
}

func GetRemediationSummary(issues []Issue) *RemediationSummary {
	summary := &RemediationSummary{
		Upgrades:   []*UpgradeGroup{},
		Pins:       []*PinGroup{},
		Unresolved: []Issue{},
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

		if fixAttrs.Outcome == Unresolved {
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
		case UpgradePackageAdvice:
			if !processUpgradeAdvice(issue, advice, fixAttrs.Outcome, upgradeMap) {
				summary.Unresolved = append(summary.Unresolved, issue)
			}
		case PinPackageAdvice:
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

func getFixAttributes(issue Issue) *FixAttributes {
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

func processUpgradeAdvice(issue Issue, advice UpgradePackageAdvice, outcome FixAppliedOutcome, upgradeMap map[string]*UpgradeGroup) bool {
	if len(advice.UpgradePaths) == 0 {
		return false
	}

	depPaths, ok := issue.GetData(DataKeyDependencyPaths)
	if !ok || depPaths == nil {
		return false
	}

	paths, ok := depPaths.([][]Package)
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
	return outcome == FullyResolved || !hasUnmatchedPaths
}

func addOrUpdateUpgradeGroup(upgradeMap map[string]*UpgradeGroup, key string, fromPkg, toPkg Package, issue Issue) {
	if existing, exists := upgradeMap[key]; exists {
		if !containsIssue(existing.Fixes, issue) {
			existing.Fixes = append(existing.Fixes, issue)
		}
		if compareVersions(toPkg.Version, existing.ToPackage.Version) > 0 {
			existing.ToPackage.Version = toPkg.Version
		}
	} else {
		upgradeMap[key] = &UpgradeGroup{
			FromPackage: fromPkg,
			ToPackage:   toPkg,
			Fixes:       []Issue{issue},
		}
	}
}

func processPinAdvice(issue Issue, advice PinPackageAdvice, pinMap map[string][]*PinGroup) {
	vulnerablePkg := getVulnerablePackage(issue)
	key := vulnerablePkg.Name
	toPkg := Package{Name: advice.PackageName, Version: advice.PinVersion}

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
				if !containsIssue(pin.Fixes, issue) {
					pin.Fixes = append(pin.Fixes, issue)
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
				ToPackage:   Package{Name: toPkg.Name, Version: highestToVersion},
				Fixes:       []Issue{issue},
			})
		}
	} else {
		pinMap[key] = []*PinGroup{{
			FromPackage: vulnerablePkg,
			ToPackage:   toPkg,
			Fixes:       []Issue{issue},
		}}
	}
}

func getVulnerablePackage(issue Issue) Package {
	if componentName, ok := issue.GetData(DataKeyComponentName); ok {
		if name, ok := componentName.(string); ok {
			version := ""
			if componentVersion, ok := issue.GetData(DataKeyComponentVersion); ok {
				if v, ok := componentVersion.(string); ok {
					version = v
				}
			}
			return Package{Name: name, Version: version}
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

	return Package{}
}

func pathsMatch(upgradePath, depPath []Package) bool {
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

func containsIssue(issues []Issue, issue Issue) bool {
	issueID := issue.GetID()
	issueVersion, _ := issue.GetData(DataKeyComponentVersion)

	for _, existing := range issues {
		if existing.GetID() != issueID {
			continue
		}
		existingVersion, _ := existing.GetData(DataKeyComponentVersion)
		if issueVersion == existingVersion {
			return true
		}
	}
	return false
}

// TODO: this must use semver to compare versions (depends on the package manager?)
func compareVersions(v1, v2 string) int {
	return strings.Compare(v1, v2)
}
