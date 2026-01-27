package ufm_helpers

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/require"
)

func TestGetRemediationSummary(t *testing.T) {
	t.Run("no issues returns empty summary", func(t *testing.T) {
		summary := GetRemediationSummary([]testapi.Issue{})

		require.Empty(t, summary.Upgrades)
		require.Empty(t, summary.Pins)
		require.Empty(t, summary.Unresolved)
	})

	t.Run("an issue containing no fix action returns empty summary", func(t *testing.T) {
		issues := []testapi.Issue{
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
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withPinFix(testapi.FullyResolved, "vulnerable", "1.0.1"),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Pins, 1)
			require.Equal(t, "vulnerable", summary.Pins[0].FromPackage.Name)
			require.Equal(t, "1.0.0", summary.Pins[0].FromPackage.Version)
			require.Equal(t, "vulnerable", summary.Pins[0].ToPackage.Name)
			require.Equal(t, "1.0.1", summary.Pins[0].ToPackage.Version)
			require.Len(t, summary.Pins[0].FixedIssues, 1)
			require.Empty(t, summary.Upgrades)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("two pins for two different packages returns valid summary", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withPinFix(testapi.FullyResolved, "vulnerable", "1.0.1"),
				),
				newTestIssue(t, "VULN_ID_2", "vulnerable-2@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable-2@1.0.0"),
					withPinFix(testapi.FullyResolved, "vulnerable-2", "1.0.2"),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Pins, 2)
			require.Empty(t, summary.Upgrades)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("two pins for the same package with different vulns merge into one pin", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withPinFix(testapi.FullyResolved, "vulnerable", "1.0.1"),
				),
				newTestIssue(t, "VULN_ID_2", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withPinFix(testapi.FullyResolved, "vulnerable", "1.0.2"),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Pins, 1)
			require.Equal(t, "vulnerable", summary.Pins[0].FromPackage.Name)
			require.Equal(t, "1.0.2", summary.Pins[0].ToPackage.Version) // Should be the higher version
			require.Len(t, summary.Pins[0].FixedIssues, 2)
			require.Empty(t, summary.Upgrades)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("a pin with multiple dependency paths returns valid summary", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "vulnerable@1.0.0"),
					withPinFix(testapi.FullyResolved, "vulnerable", "1.0.1"),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Pins, 1)
			require.Equal(t, "vulnerable", summary.Pins[0].FromPackage.Name)
			require.Equal(t, "1.0.0", summary.Pins[0].FromPackage.Version)
			require.Equal(t, "1.0.1", summary.Pins[0].ToPackage.Version)
			require.Len(t, summary.Pins[0].FixedIssues, 1)
			require.Empty(t, summary.Upgrades)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("two pins for the same package with same vuln but different versions create two pins", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withPinFix(testapi.FullyResolved, "vulnerable", "1.0.1"),
				),
				newTestIssue(t, "VULN_ID_1", "vulnerable@2.0.0",
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "vulnerable@2.0.0"),
					withPinFix(testapi.FullyResolved, "vulnerable", "2.0.1"),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Pins, 2)
			require.Empty(t, summary.Upgrades)
			require.Empty(t, summary.Unresolved)

			// Both pins should have the highest TO version (2.0.1)
			for _, pin := range summary.Pins {
				require.Equal(t, "vulnerable", pin.FromPackage.Name)
				require.Equal(t, "2.0.1", pin.ToPackage.Version)
			}
		})
	})

	t.Run("upgrades", func(t *testing.T) {
		t.Run("upgrade for single package with single path returns valid summary", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(testapi.FullyResolved, []string{"root@1.0.0", "direct@1.2.3", "vulnerable@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Equal(t, "direct", summary.Upgrades[0].FromPackage.Name)
			require.Equal(t, "1.0.0", summary.Upgrades[0].FromPackage.Version)
			require.Equal(t, "direct", summary.Upgrades[0].ToPackage.Name)
			require.Equal(t, "1.2.3", summary.Upgrades[0].ToPackage.Version)
			require.Len(t, summary.Upgrades[0].FixedIssues, 1)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("upgrade with drop for single package returns valid summary", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(testapi.FullyResolved, []string{"root@1.0.0", "direct@1.2.3"}), // Drop - shorter path
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
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(testapi.FullyResolved,
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
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "transitive-1@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(testapi.PartiallyResolved, []string{"root@1.0.0", "direct-1@1.2.3", "vulnerable@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Equal(t, "direct-1", summary.Upgrades[0].FromPackage.Name)
			require.Empty(t, summary.Pins)
			require.Len(t, summary.Unresolved, 1)
		})

		t.Run("upgrade for single package with fully resolved fix results returns upgrade and NO unresolved", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "transitive-1@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(testapi.FullyResolved, []string{"root@1.0.0", "direct-1@1.2.3", "vulnerable@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved, "FullyResolved should NOT add to unresolved")
		})

		t.Run("upgrade for single package with multiple vulns returns valid summary", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(testapi.FullyResolved, []string{"root@1.0.0", "direct@1.2.3", "vulnerable@1.0.1"}),
				),
				newTestIssue(t, "VULN_ID_2", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(testapi.FullyResolved, []string{"root@1.0.0", "direct@1.2.3", "vulnerable@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Len(t, summary.Upgrades[0].FixedIssues, 2)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("upgrade for multiple packages with multiple vulns returns valid summary with merged upgrades", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable-1@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable-1@1.0.0"),
					withUpgradeFix(testapi.FullyResolved, []string{"root@1.0.0", "direct@1.2.3", "vulnerable-1@1.0.1"}),
				),
				newTestIssue(t, "VULN_ID_2", "vulnerable-2@1.0.0",
					withDepPaths("root@1.0.0", "direct@1.0.0", "vulnerable-2@1.0.0"),
					withUpgradeFix(testapi.FullyResolved, []string{"root@1.0.0", "direct@1.4.0", "vulnerable-2@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Equal(t, "direct", summary.Upgrades[0].FromPackage.Name)
			require.Equal(t, "1.4.0", summary.Upgrades[0].ToPackage.Version) // Should be the higher version
			require.Len(t, summary.Upgrades[0].FixedIssues, 2)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("upgrades for multiple packages to different direct deps returns multiple upgrades", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID_1", "vulnerable-1@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable-1@1.0.0"),
					withUpgradeFix(testapi.FullyResolved, []string{"root@1.0.0", "direct-1@1.2.3", "vulnerable-1@1.0.1"}),
				),
				newTestIssue(t, "VULN_ID_2", "vulnerable-2@1.0.0",
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "vulnerable-2@1.0.0"),
					withUpgradeFix(testapi.FullyResolved, []string{"root@1.0.0", "direct-2@1.4.0", "vulnerable-2@1.0.1"}),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 2)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("upgrades for single package with multiple resolved paths of different lengths returns valid summary", func(t *testing.T) {
			// This tests that path matching works correctly when upgrade paths
			// don't match dep paths in order or length
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
					withDepPaths("root@1.0.0", "direct-2@1.0.0", "transitive-1@1.0.0", "vulnerable@1.0.0"),
					// Note: upgrade paths are in reverse order compared to dep paths
					withUpgradeFix(testapi.FullyResolved,
						[]string{"root@1.0.0", "direct-2@1.0.5", "transitive-1@1.0.4", "vulnerable@1.0.1"},
						[]string{"root@1.0.0", "direct-1@1.2.3", "vulnerable@1.0.1"},
					),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 2)
			require.Empty(t, summary.Pins)
			require.Empty(t, summary.Unresolved)
		})

		t.Run("upgrade for single package with multiple paths pointing to same direct dep does not duplicate fixes", func(t *testing.T) {
			issues := []testapi.Issue{
				newTestIssue(t, "VULN_ID", "vulnerable@1.0.0",
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
					withDepPaths("root@1.0.0", "direct-1@1.0.0", "another-transitive@1.0.0", "vulnerable@1.0.0"),
					withUpgradeFix(testapi.PartiallyResolved,
						[]string{"root@1.0.0", "direct-1@1.2.3", "vulnerable@1.0.1"},
						[]string{"root@1.0.0", "direct-1@1.2.3", "another-transitive@1.0.0", "vulnerable@1.0.1"},
					),
				),
			}

			summary := GetRemediationSummary(issues)

			require.Len(t, summary.Upgrades, 1)
			require.Equal(t, "direct-1", summary.Upgrades[0].FromPackage.Name)
			require.Equal(t, "1.0.0", summary.Upgrades[0].FromPackage.Version)
			require.Equal(t, "1.2.3", summary.Upgrades[0].ToPackage.Version)
			// The fix should only be added once, not duplicated
			require.Len(t, summary.Upgrades[0].FixedIssues, 1)
			require.Empty(t, summary.Pins)
		})
	})

	t.Run("unresolved", func(t *testing.T) {
		t.Run("an issue containing an unresolved fix action returns valid summary", func(t *testing.T) {
			issues := []testapi.Issue{
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

// Test helpers

type issueOption func(*testapi.FindingData)

func withDepPaths(path ...string) issueOption {
	return func(f *testapi.FindingData) {
		var ev testapi.Evidence
		_ = ev.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
			Source: "dependency_path",
			Path:   parsePath(path),
		})
		f.Attributes.Evidence = append(f.Attributes.Evidence, ev)
	}
}

func withUpgradeFix(outcome testapi.FixAppliedOutcome, paths ...[]string) issueOption {
	return func(f *testapi.FindingData) {
		var upgradePaths []testapi.UpgradePath
		for _, path := range paths {
			upgradePaths = append(upgradePaths, testapi.UpgradePath{
				DependencyPath: parsePath(path),
				IsDrop:         false,
			})
		}

		var action testapi.FixAction
		_ = action.FromUpgradePackageAdvice(testapi.UpgradePackageAdvice{
			Format:       testapi.UpgradePackageAdviceFormatUpgradePackageAdvice,
			PackageName:  "vulnerable",
			UpgradePaths: upgradePaths,
		})

		setFix(f, outcome, &action)
	}
}

func withPinFix(outcome testapi.FixAppliedOutcome, pkgName, pinVersion string) issueOption {
	return func(f *testapi.FindingData) {
		var action testapi.FixAction
		_ = action.FromPinPackageAdvice(testapi.PinPackageAdvice{
			Format:      testapi.PinPackageAdviceFormatPinPackageAdvice,
			PackageName: pkgName,
			PinVersion:  pinVersion,
		})

		setFix(f, outcome, &action)
	}
}

func withUnresolvedFix() issueOption {
	return func(f *testapi.FindingData) {
		setFix(f, testapi.Unresolved, nil)
	}
}

func setFix(f *testapi.FindingData, outcome testapi.FixAppliedOutcome, action *testapi.FixAction) {
	f.Relationships = &struct {
		Asset *struct {
			Data *struct {
				Id   uuid.UUID `json:"id"`
				Type string    `json:"type"`
			} `json:"data,omitempty"`
			Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
			Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
		} `json:"asset,omitempty"`
		Fix *struct {
			Data *struct {
				Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
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
				Attributes *testapi.PolicyAttributes `json:"attributes,omitempty"`
				Id         uuid.UUID         `json:"id"`
				Type       string            `json:"type"`
			} `json:"data,omitempty"`
			Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
			Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
		} `json:"policy,omitempty"`
		Test *struct {
			Data *struct {
				Id   uuid.UUID `json:"id"`
				Type string    `json:"type"`
			} `json:"data,omitempty"`
			Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
			Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
		} `json:"test,omitempty"`
	}{
		Fix: &struct {
			Data *struct {
				Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
				Id         uuid.UUID      `json:"id"`
				Type       string         `json:"type"`
			} `json:"data,omitempty"`
		}{
			Data: &struct {
				Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
				Id         uuid.UUID      `json:"id"`	
				Type       string         `json:"type"`
			}{
				Attributes: &testapi.FixAttributes{Outcome: outcome, Action: action},
			},
		},
	}
}

func newTestIssue(t *testing.T, vulnID, pkg string, opts ...issueOption) testapi.Issue {
	t.Helper()

	pkgName, pkgVersion := parsePkg(pkg)
	findingID := uuid.New()
	now := time.Now()

	var loc testapi.FindingLocation
	_ = loc.FromPackageLocation(testapi.PackageLocation{
		Type:    "package",
		Package: testapi.Package{Name: pkgName, Version: pkgVersion},
	})

	var problem testapi.Problem
	_ = problem.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:                       vulnID,
		Source:                   "snyk_vuln",
		Severity:                 testapi.SeverityHigh,
		CvssBaseScore:            7.5,
		CvssVector:               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		CreatedAt:                now,
		ModifiedAt:               now,
		PublishedAt:              now,
		DisclosedAt:              now,
		PackageName:              pkgName,
		PackageVersion:           pkgVersion,
		IsFixable:                true,
		IsMalicious:              false,
		IsSocialMediaTrending:    false,
		Credits:                  []string{},
		References:               []testapi.SnykvulndbReferenceLinks{},
		CvssSources:              []testapi.SnykvulndbCvssSource{},
		InitiallyFixedInVersions: []string{"1.0.1"},
		ExploitDetails:           testapi.SnykvulndbExploitDetails{MaturityLevels: []testapi.SnykvulndbExploitMaturityLevel{}, Sources: []string{}},
	})

	finding := &testapi.FindingData{
		Id: &findingID,
		Attributes: &testapi.FindingAttributes{
			FindingType: testapi.FindingTypeSca,
			Key:         vulnID,
			Title:       "Test vulnerability " + vulnID,
			Description: "Description for " + vulnID,
			Rating:      testapi.Rating{Severity: testapi.SeverityHigh},
			Problems:    []testapi.Problem{problem},
			Locations:   []testapi.FindingLocation{loc},
		},
	}

	for _, opt := range opts {
		opt(finding)
	}

	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{finding})
	require.NoError(t, err)
	return issue
}

func parsePath(path []string) []testapi.Package {
	var pkgs []testapi.Package
	for _, p := range path {
		name, version := parsePkg(p)
		pkgs = append(pkgs, testapi.Package{Name: name, Version: version})
	}
	return pkgs
}

func parsePkg(s string) (string, string) {
	parts := strings.Split(s, "@")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return s, ""
}
