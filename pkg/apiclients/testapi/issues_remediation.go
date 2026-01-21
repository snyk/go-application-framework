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
	pinMap := make(map[string]*PinGroup)

	for _, issue := range issues {
		// Skip ignored issues
		if ignoreDetails := issue.GetIgnoreDetails(); ignoreDetails != nil && ignoreDetails.IsActive() {
			continue
		}

		fixInfo := extractFixInfo(issue)
		if fixInfo == nil {
			continue
		}

		switch fixInfo.FixType {
		case fixTypeUpgrade:
			wasAdded, hasUnresolvedPaths := processUpgradeFix(issue, fixInfo, upgradeMap)
			if !wasAdded || (hasUnresolvedPaths && fixInfo.Outcome != FullyResolved) {
				summary.Unresolved = append(summary.Unresolved, issue)
			}
		case fixTypePin:
			processPinFix(issue, fixInfo, pinMap)
		case fixTypeUnresolved:
			summary.Unresolved = append(summary.Unresolved, issue)
		}
	}

	for _, upgrade := range upgradeMap {
		summary.Upgrades = append(summary.Upgrades, upgrade)
	}
	for _, pin := range pinMap {
		summary.Pins = append(summary.Pins, pin)
	}

	return summary
}

type fixType int

const (
	fixTypeUnresolved fixType = iota
	fixTypeUpgrade
	fixTypePin
)

type fixInfo struct {
	FixType      fixType
	FromPackage  Package
	ToPackage    Package
	UpgradePaths []UpgradePath
	Outcome      FixAppliedOutcome
}

func extractFixInfo(issue Issue) *fixInfo {
	findings := issue.GetFindings()
	if len(findings) == 0 {
		return nil
	}

	finding := findings[0]
	if finding.Relationships == nil ||
		finding.Relationships.Fix == nil ||
		finding.Relationships.Fix.Data == nil ||
		finding.Relationships.Fix.Data.Attributes == nil {
		return nil
	}

	fixAttrs := finding.Relationships.Fix.Data.Attributes
	outcome := fixAttrs.Outcome

	if outcome == Unresolved {
		return &fixInfo{FixType: fixTypeUnresolved, Outcome: outcome}
	}

	if fixAttrs.Action == nil {
		return nil
	}

	discriminator, err := fixAttrs.Action.Discriminator()
	if err != nil {
		return nil
	}

	vulnerablePkg := getVulnerablePackage(issue)

	switch discriminator {
	case string(UpgradePackageAdviceFormatUpgradePackageAdvice):
		upgradeAdvice, err := fixAttrs.Action.AsUpgradePackageAdvice()
		if err != nil {
			return nil
		}
		return &fixInfo{
			FixType:      fixTypeUpgrade,
			FromPackage:  vulnerablePkg,
			UpgradePaths: upgradeAdvice.UpgradePaths,
			Outcome:      outcome,
		}

	case string(PinPackageAdviceFormatPinPackageAdvice):
		pinAdvice, err := fixAttrs.Action.AsPinPackageAdvice()
		if err != nil {
			return nil
		}
		return &fixInfo{
			FixType:     fixTypePin,
			FromPackage: vulnerablePkg,
			ToPackage: Package{
				Name:    pinAdvice.PackageName,
				Version: pinAdvice.PinVersion,
			},
			Outcome: outcome,
		}
	}

	return nil
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

func processUpgradeFix(issue Issue, fix *fixInfo, upgradeMap map[string]*UpgradeGroup) (wasAdded bool, hasUnresolvedPaths bool) {
	if len(fix.UpgradePaths) == 0 {
		return false, true
	}

	depPaths, ok := issue.GetData(DataKeyDependencyPaths)
	if !ok || depPaths == nil {
		return false, true
	}

	paths, ok := depPaths.([][]Package)
	if !ok || len(paths) == 0 {
		return false, true
	}

	matchedDepPaths := make(map[int]bool)

	for _, upgradePath := range fix.UpgradePaths {
		if len(upgradePath.DependencyPath) < 2 {
			continue
		}

		for depIdx, depPath := range paths {
			if len(depPath) < 2 {
				continue
			}

			if !pathsMatch(upgradePath.DependencyPath, depPath) {
				continue
			}

			matchedDepPaths[depIdx] = true

			fromPkg := depPath[1]
			toPkg := upgradePath.DependencyPath[1]

			key := fmt.Sprintf("%s@%s", fromPkg.Name, fromPkg.Version)

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
			wasAdded = true
			break
		}
	}

	hasUnresolvedPaths = len(matchedDepPaths) < len(paths)

	return wasAdded, hasUnresolvedPaths
}

func processPinFix(issue Issue, fix *fixInfo, pinMap map[string]*PinGroup) {
	key := fmt.Sprintf("%s@%s", fix.FromPackage.Name, fix.FromPackage.Version)

	if existing, exists := pinMap[key]; exists {
		if !containsIssue(existing.Fixes, issue) {
			existing.Fixes = append(existing.Fixes, issue)
		}
		if compareVersions(fix.ToPackage.Version, existing.ToPackage.Version) > 0 {
			existing.ToPackage.Version = fix.ToPackage.Version
		}
	} else {
		pinMap[key] = &PinGroup{
			FromPackage: fix.FromPackage,
			ToPackage:   fix.ToPackage,
			Fixes:       []Issue{issue},
		}
	}
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
	for _, existing := range issues {
		if existing.GetID() == issue.GetID() {
			return true
		}
	}
	return false
}

func compareVersions(v1, v2 string) int {
	return strings.Compare(v1, v2)
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

func (s *RemediationSummary) TotalFixableIssues() int {
	count := 0
	for _, upgrade := range s.Upgrades {
		count += len(upgrade.Fixes)
	}
	for _, pin := range s.Pins {
		count += len(pin.Fixes)
	}
	return count
}
