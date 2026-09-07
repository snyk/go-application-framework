package toon_test

import (
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters/toon"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
)

func loadTestResults(t *testing.T, path string) []testapi.TestResult {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	results, err := ufm.NewSerializableTestResultFromBytes(raw)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	return results
}

func sectionCell(t *testing.T, section toon.Section, row int, column string) string {
	t.Helper()
	require.Less(t, row, len(section.Rows), "row index out of range")
	for i, col := range section.Columns {
		if col.Name == column {
			return section.Rows[row][i]
		}
	}
	require.Failf(t, "unknown column %q", column)
	return ""
}

func TestProjectSCA_fixture(t *testing.T) {
	t.Parallel()

	section, err := toon.ProjectSCA(loadTestResults(t, "../testdata/ufm/sca.toon.testresult.json"))
	require.NoError(t, err)

	assert.Equal(t, "sca", section.Name)
	assert.Len(t, section.Rows, 3)
	assert.Equal(t, "SNYK-JS-EJS-6689533", sectionCell(t, section, 0, "id"))
	assert.Equal(t, "medium", sectionCell(t, section, 0, "severity"))
	assert.Equal(t, "ejs@1.0.0", sectionCell(t, section, 0, "pkg"))
	assert.Equal(t, "yes", sectionCell(t, section, 0, "fixable"))
	assert.Equal(t, "SNYK-JS-LODASH-1018905", sectionCell(t, section, 1, "id"))
	assert.Equal(t, "high", sectionCell(t, section, 1, "severity"))
	assert.Equal(t, "lodash@4.17.4", sectionCell(t, section, 1, "pkg"))
	assert.Equal(t, "no", sectionCell(t, section, 1, "fixable"))
	assert.Equal(t, "SNYK-JS-QS-3153490", sectionCell(t, section, 2, "id"))
	assert.Equal(t, "low", sectionCell(t, section, 2, "severity"))
	assert.Equal(t, "qs@0.0.6", sectionCell(t, section, 2, "pkg"))
	assert.Equal(t, "yes", sectionCell(t, section, 2, "fixable"))
	assert.Equal(t, "3 unique vulns (4 paths) | 1 high 1 medium 1 low | 2 fixable", section.Summary)
}

func TestProjectSCA_empty(t *testing.T) {
	t.Parallel()

	section, err := toon.ProjectSCA(nil)
	require.NoError(t, err)
	assert.Empty(t, section.Rows)
	assert.Equal(t, "0 vulnerabilities found", section.Summary)
}

func TestProjectSCA_multiVersionPkg(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mock := mocks.NewMockTestResult(ctrl)
	findings := []testapi.FindingData{
		*scaFinding("SNYK-JS-LODASH-590103", "lodash", "4.17.10", true),
		*scaFinding("SNYK-JS-LODASH-590103", "lodash", "4.17.4", false),
	}
	mock.EXPECT().Findings(gomock.Any()).Return(findings, true, nil)

	section, err := toon.ProjectSCA([]testapi.TestResult{mock})
	require.NoError(t, err)

	require.Len(t, section.Rows, 1)
	assert.Equal(t, "lodash@4.17.4,4.17.10", sectionCell(t, section, 0, "pkg"))
	assert.Equal(t, "yes", sectionCell(t, section, 0, "fixable"))
}

func TestProjectSCA_fixableWhenAnyPathFixable(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mock := mocks.NewMockTestResult(ctrl)
	findings := []testapi.FindingData{
		*scaFinding("SNYK-JS-EJS-6689533", "ejs", "1.0.0", false),
		*scaFinding("SNYK-JS-EJS-6689533", "ejs", "1.0.0", true),
	}
	mock.EXPECT().Findings(gomock.Any()).Return(findings, true, nil)

	section, err := toon.ProjectSCA([]testapi.TestResult{mock})
	require.NoError(t, err)

	require.Len(t, section.Rows, 1)
	assert.Equal(t, "yes", sectionCell(t, section, 0, "fixable"))
	assert.Equal(t, "1 unique vulns (2 paths) | 1 medium | 1 fixable", section.Summary)
}

func TestProjectSecrets_fixture(t *testing.T) {
	t.Parallel()

	section, err := toon.ProjectSecrets(loadTestResults(t, "../testdata/ufm/secrets.toon.testresult.json"))
	require.NoError(t, err)

	assert.Equal(t, "secrets", section.Name)
	assert.Len(t, section.Rows, 2)
	assert.Equal(t, "AWS Access Token", sectionCell(t, section, 0, "rule"))
	assert.Equal(t, "critical", sectionCell(t, section, 0, "severity"))
	assert.Equal(t, "app.py", sectionCell(t, section, 0, "file"))
	assert.Equal(t, "1", sectionCell(t, section, 0, "line"))
	assert.Equal(t, "Slack Bot Token", sectionCell(t, section, 1, "rule"))
	assert.Equal(t, "high", sectionCell(t, section, 1, "severity"))
	assert.Equal(t, "app.py", sectionCell(t, section, 1, "file"))
	assert.Equal(t, "5", sectionCell(t, section, 1, "line"))
	assert.Equal(t, "2 secrets | 1 critical 1 high", section.Summary)
}

func TestProjectSecrets_empty(t *testing.T) {
	t.Parallel()

	section, err := toon.ProjectSecrets(nil)
	require.NoError(t, err)
	assert.Empty(t, section.Rows)
	assert.Equal(t, "0 secrets found", section.Summary)
}

func TestProjectSecrets_specialCharactersPreserved(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mock := mocks.NewMockTestResult(ctrl)
	findings := []testapi.FindingData{
		*secretsFinding("rule,with\"comma\"", "src/with space.go", 42, "high"),
	}
	mock.EXPECT().Findings(gomock.Any()).Return(findings, true, nil)

	section, err := toon.ProjectSecrets([]testapi.TestResult{mock})
	require.NoError(t, err)

	require.Len(t, section.Rows, 1)
	assert.Equal(t, "rule,with\"comma\"", sectionCell(t, section, 0, "rule"))
	assert.Equal(t, "src/with space.go", sectionCell(t, section, 0, "file"))
}

func scaFinding(id, name, version string, fixable bool) *testapi.FindingData {
	var pkgLoc testapi.FindingLocation
	if err := pkgLoc.MergePackageLocation(testapi.PackageLocation{
		Type:    testapi.PackageLocationTypePackage,
		Package: testapi.Package{Name: name, Version: version},
	}); err != nil {
		panic(err)
	}

	var problem testapi.Problem
	if err := problem.MergeSnykVulnProblem(testapi.SnykVulnProblem{
		Id:        id,
		Severity:  testapi.SeverityMedium,
		IsFixable: fixable,
	}); err != nil {
		panic(err)
	}

	return &testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			FindingType: testapi.FindingTypeSca,
			Key:         id,
			Problems:    []testapi.Problem{problem},
			Locations:   []testapi.FindingLocation{pkgLoc},
			Rating:      testapi.Rating{Severity: testapi.SeverityMedium},
		},
		Id: ptrUUID(),
	}
}

func secretsFinding(rule, file string, line int, severity string) *testapi.FindingData {
	var srcLoc testapi.FindingLocation
	if err := srcLoc.MergeSourceLocation(testapi.SourceLocation{
		Type:     testapi.SourceLocationTypeSource,
		FilePath: file,
		FromLine: line,
	}); err != nil {
		panic(err)
	}

	return &testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			FindingType: testapi.FindingTypeSecrets,
			Key:         rule,
			Title:       rule,
			Locations:   []testapi.FindingLocation{srcLoc},
			Rating:      testapi.Rating{Severity: testapi.Severity(severity)},
		},
		Id: ptrUUID(),
	}
}

func ptrUUID() *uuid.UUID {
	id := uuid.New()
	return &id
}
