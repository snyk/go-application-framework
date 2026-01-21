package testapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestGetRemediationSummary(t *testing.T) {
	t.Run("no issues returns empty summary", func(t *testing.T) {
		summary := GetRemediationSummary([]Issue{})

		require.Empty(t, summary.Upgrades)
		require.Empty(t, summary.Pins)
		require.Empty(t, summary.Unresolved)
	})

	t.Run("an issue containing no fix action returns empty summary", func(t *testing.T) {
		issues := []Issue{
			newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
				withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
			),
		}

		summary := GetRemediationSummary(issues)

		require.Empty(t, summary.Upgrades)
		require.Empty(t, summary.Pins)
		require.Empty(t, summary.Unresolved)
	})

	t.Run("pins", func(t *testing.T) {
		t.Run("single pin for single package returns valid summary", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withPinFix(FullyResolved, "vulnerable", "1.0.1"),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Pins, 1)
			require.Equal(t, "vulnerable", summary.Pins[0].FromPackage.Name)
			require.Equal(t, "1.0.0", summary.Pins[0].FromPackage.Version)
			require.Equal(t, "vulnerable", summary.Pins[0].ToPackage.Name)
			require.Equal(t, "1.0.1", summary.Pins[0].ToPackage.Version)
			require.Len(t, summary.Pins[0].Fixes, 1)
			require.Empty(t, summary.Upgrades)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("two pins for two different packages returns valid summary", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withPinFix(FullyResolved, "vulnerable", "1.0.1"),
				),
				newTestIssue(t, "VULN_ID_2", "vulnerable-2@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable-2@1.0.0"),
					withPinFix(FullyResolved, "vulnerable-2", "1.0.2"),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Pins, 2)
			require.Empty(t, summary.Upgrades)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("two pins for the same package with different vulns merge into one pin", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withPinFix(FullyResolved, "vulnerable", "1.0.1"),
				),
				newTestIssue(t, "VULN_ID_2", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withPinFix(FullyResolved, "vulnerable", "1.0.2"),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Pins, 1)
			require.Equal(t, "vulnerable", summary.Pins[0].FromPackage.Name)
			require.Equal(t, "1.0.2", summary.Pins[0].ToPackage.Version) // Should be the higher version
			require.Len(t, summary.Pins[0].Fixes, 2)
			require.Empty(t, summary.Upgrades)
			require.Empty(t, summary.Unresolved)
		})
	})

	t.Run("upgrades", func(t *testing.T) {
		t.Run("upgrade for single package with single path returns valid summary", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(FullyResolved, []string{"root@1.0.0", "direct@1.2.3", "vulnerable@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Equal(t, "direct", summary.Upgrades[0].FromPackage.Name)
			require.Equal(t, "1.0.0", summary.Upgrades[0].FromPackage.Version)
			require.Equal(t, "direct", summary.Upgrades[0].ToPackage.Name)
			require.Equal(t, "1.2.3", summary.Upgrades[0].ToPackage.Version)
			require.Len(t, summary.Upgrades[0].Fixes, 1)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("upgrade with drop for single package returns valid summary", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(FullyResolved, []string{"root@1.0.0", "direct@1.2.3"}), // Drop - shorter path
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Equal(t, "direct", summary.Upgrades[0].FromPackage.Name)
			require.Equal(t, "1.0.0", summary.Upgrades[0].FromPackage.Version)
			require.Equal(t, "direct", summary.Upgrades[0].ToPackage.Name)
			require.Equal(t, "1.2.3", summary.Upgrades[0].ToPackage.Version)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("upgrades for single package with multiple resolved paths returns valid summary", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(FullyResolved,
						[]string{"root@1.0.0", "direct-1@1.2.3", "vulnerable@1.0.1"},
						[]string{"root@1.0.0", "direct-2@1.0.5", "vulnerable@1.0.1"},
					),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 2)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("upgrade for single package with an unresolved path and a resolved path returns upgrade and unresolved", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "transitive-1@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(PartiallyResolved, []string{"root@1.0.0", "direct-1@1.2.3", "vulnerable@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Equal(t, "direct-1", summary.Upgrades[0].FromPackage.Name)
			require.Empty(t, summary.Pins)
			require.Len(t, summary.Unresolved, 1)
		})

		t.Run("upgrade for single package with fully resolved fix results returns upgrade and NO unresolved", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "transitive-1@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(FullyResolved, []string{"root@1.0.0", "direct-1@1.2.3", "vulnerable@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved, "FullyResolved should NOT add to unresolved")
		})

		t.Run("upgrade for single package with multiple vulns returns valid summary", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(FullyResolved, []string{"root@1.0.0", "direct@1.2.3", "vulnerable@1.0.1"}),
				),
				newTestIssue(t, "VULN_ID_2", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(FullyResolved, []string{"root@1.0.0", "direct@1.2.3", "vulnerable@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Len(t, summary.Upgrades[0].Fixes, 2)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("upgrade for multiple packages with multiple vulns returns valid summary with merged upgrades", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable-1@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable-1@1.0.0"),
					withUpgradeFix(FullyResolved, []string{"root@1.0.0", "direct@1.2.3", "vulnerable-1@1.0.1"}),
				),
				newTestIssue(t, "VULN_ID_2", "vulnerable-2@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable-2@1.0.0"),
					withUpgradeFix(FullyResolved, []string{"root@1.0.0", "direct@1.4.0", "vulnerable-2@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Equal(t, "direct", summary.Upgrades[0].FromPackage.Name)
			require.Equal(t, "1.4.0", summary.Upgrades[0].ToPackage.Version) // Should be the higher version
			require.Len(t, summary.Upgrades[0].Fixes, 2)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("upgrades for multiple packages to different direct deps returns multiple upgrades", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable-1@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable-1@1.0.0"),
					withUpgradeFix(FullyResolved, []string{"root@1.0.0", "direct-1@1.2.3", "vulnerable-1@1.0.1"}),
				),
				newTestIssue(t, "VULN_ID_2", "vulnerable-2@1.0.0",
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "vulnerable-2@1.0.0"),
					withUpgradeFix(FullyResolved, []string{"root@1.0.0", "direct-2@1.4.0", "vulnerable-2@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 2)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})
	})

	t.Run("unresolved", func(t *testing.T) {
		t.Run("an issue containing an unresolved fix action returns valid summary", func(t *testing.T) {
			issues := []Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
					withUnresolvedFix(),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Empty(t, summary.Upgrades)
			require.Empty(t, summary.Pins)
			require.Len(t, summary.Unresolved, 1)
		})
	})
}

// Test helper types and functions

type issueOption func(*FindingData)

func withDepPaths(path ...string) issueOption {
	return func(f *FindingData) {
		var pathPkgs []Package
		for _, p := range path {
			name, version := splitNameAndVersion(p)
			pathPkgs = append(pathPkgs, Package{Name: name, Version: version})
		}
		evJSON := createDependencyPathJSON(pathPkgs)
		var ev Evidence
		_ = json.Unmarshal([]byte(evJSON), &ev)
		f.Attributes.Evidence = append(f.Attributes.Evidence, ev)
	}
}

func withUpgradeFix(outcome FixAppliedOutcome, paths ...[]string) issueOption {
	return func(f *FindingData) {
		var upgradePaths []string
		for _, path := range paths {
			var pathPkgs []string
			for _, p := range path {
				name, version := splitNameAndVersion(p)
				pathPkgs = append(pathPkgs, `{"name": "`+name+`", "version": "`+version+`"}`)
			}
			upgradePaths = append(upgradePaths, `{"dependency_path": [`+strings.Join(pathPkgs, ",")+`], "is_drop": false}`)
		}
		actionJSON := `{"format": "upgrade_package_advice", "package_name": "vulnerable", "upgrade_paths": [` + strings.Join(upgradePaths, ",") + `]}`

		var action FixAction
		_ = json.Unmarshal([]byte(actionJSON), &action)

		setFixRelationship(f, &FixAttributes{Outcome: outcome, Action: &action})
	}
}

func withPinFix(outcome FixAppliedOutcome, pkgName, pinVersion string) issueOption {
	return func(f *FindingData) {
		actionJSON := `{"format": "pin_package_advice", "package_name": "` + pkgName + `", "pin_version": "` + pinVersion + `"}`
		var action FixAction
		_ = json.Unmarshal([]byte(actionJSON), &action)

		setFixRelationship(f, &FixAttributes{Outcome: outcome, Action: &action})
	}
}

func withUnresolvedFix() issueOption {
	return func(f *FindingData) {
		setFixRelationship(f, &FixAttributes{Outcome: Unresolved})
	}
}

func setFixRelationship(f *FindingData, attrs *FixAttributes) {
	f.Relationships = &struct {
		Asset *struct {
			Data *struct {
				Id   uuid.UUID `json:"id"`
				Type string    `json:"type"`
			} `json:"data,omitempty"`
			Links IoSnykApiCommonRelatedLink `json:"links"`
			Meta  *IoSnykApiCommonMeta       `json:"meta,omitempty"`
		} `json:"asset,omitempty"`
		Fix *struct {
			Data *struct {
				Attributes *FixAttributes `json:"attributes,omitempty"`
				Id         uuid.UUID      `json:"id"`
				Type       string         `json:"type"`
			} `json:"data,omitempty"`
		} `json:"fix,omitempty"`
		Org *struct {
			Data *struct {
				Id   uuid.UUID `json:"id"`
				Type string    `json:"type"`
			} `json:"data,omitempty"`
		} `json:"org,omitempty"`
		Policy *struct {
			Data *struct {
				Attributes *PolicyAttributes `json:"attributes,omitempty"`
				Id         uuid.UUID         `json:"id"`
				Type       string            `json:"type"`
			} `json:"data,omitempty"`
			Links IoSnykApiCommonRelatedLink `json:"links"`
			Meta  *IoSnykApiCommonMeta       `json:"meta,omitempty"`
		} `json:"policy,omitempty"`
		Test *struct {
			Data *struct {
				Id   uuid.UUID `json:"id"`
				Type string    `json:"type"`
			} `json:"data,omitempty"`
			Links IoSnykApiCommonRelatedLink `json:"links"`
			Meta  *IoSnykApiCommonMeta       `json:"meta,omitempty"`
		} `json:"test,omitempty"`
	}{
		Fix: &struct {
			Data *struct {
				Attributes *FixAttributes `json:"attributes,omitempty"`
				Id         uuid.UUID      `json:"id"`
				Type       string         `json:"type"`
			} `json:"data,omitempty"`
		}{
			Data: &struct {
				Attributes *FixAttributes `json:"attributes,omitempty"`
				Id         uuid.UUID      `json:"id"`
				Type       string         `json:"type"`
			}{
				Attributes: attrs,
			},
		},
	}
}

func newTestIssue(t *testing.T, vulnID, pkg string, opts ...issueOption) Issue {
	t.Helper()

	pkgName, pkgVersion := splitNameAndVersion(pkg)
	findingID := uuid.New()

	finding := &FindingData{
		Id: &findingID,
		Attributes: &FindingAttributes{
			FindingType: FindingTypeSca,
			Key:         vulnID,
			Title:       "Test vulnerability " + vulnID,
			Description: "Description for " + vulnID,
			Rating:      Rating{Severity: SeverityHigh},
			Problems:    []Problem{createVulnProblem(t, vulnID)},
			Locations:   []FindingLocation{createPackageLocation(t, pkgName, pkgVersion)},
		},
	}

	for _, opt := range opts {
		opt(finding)
	}

	issue, err := NewIssueFromFindings([]*FindingData{finding})
	require.NoError(t, err)
	return issue
}

func createVulnProblem(t *testing.T, vulnID string) Problem {
	t.Helper()
	var problem Problem
	problemJSON := `{
		"id": "` + vulnID + `",
		"source": "snyk_vuln",
		"severity": "high",
		"cvss_base_score": 7.5,
		"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		"ecosystem": {"type": "build_package", "language": "javascript", "package_manager": "npm"},
		"created_at": "2021-01-01T00:00:00Z",
		"modified_at": "2021-01-01T00:00:00Z",
		"published_at": "2021-01-01T00:00:00Z",
		"disclosed_at": "2021-01-01T00:00:00Z",
		"package_name": "vulnerable",
		"package_version": "1.0.0",
		"is_fixable": true,
		"is_malicious": false,
		"is_social_media_trending": false,
		"credits": [],
		"references": [],
		"cvss_sources": [],
		"initially_fixed_in_versions": ["1.0.1"],
		"exploit_details": {"maturity_levels": [], "sources": []}
	}`
	err := json.Unmarshal([]byte(problemJSON), &problem)
	require.NoError(t, err)
	return problem
}

func createPackageLocation(t *testing.T, name, version string) FindingLocation {
	t.Helper()
	var loc FindingLocation
	locJSON := `{"type": "package", "package": {"name": "` + name + `", "version": "` + version + `"}}`
	err := json.Unmarshal([]byte(locJSON), &loc)
	require.NoError(t, err)
	return loc
}

func createDependencyPathJSON(path []Package) string {
	var pathJSON []string
	for _, p := range path {
		pathJSON = append(pathJSON, `{"name": "`+p.Name+`", "version": "`+p.Version+`"}`)
	}
	return `{"source": "dependency_path", "path": [` + strings.Join(pathJSON, ",") + `]}`
}

func splitNameAndVersion(s string) (string, string) {
	parts := strings.Split(s, "@")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return s, ""
}
