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

func TestProjectSCA_fixture(t *testing.T) {
	t.Parallel()

	view, err := toon.ProjectSCA(loadTestResults(t, "../testdata/ufm/sca.toon.testresult.json"))
	require.NoError(t, err)

	assert.Len(t, view.Rows, 3)
	assert.Equal(t, "SNYK-JS-EJS-6689533", view.Rows[0].ID)
	assert.Equal(t, "medium", view.Rows[0].Severity)
	assert.Equal(t, "ejs@1.0.0", view.Rows[0].Pkg)
	assert.Equal(t, "yes", view.Rows[0].Fixable)
	assert.Equal(t, "SNYK-JS-LODASH-1018905", view.Rows[1].ID)
	assert.Equal(t, "high", view.Rows[1].Severity)
	assert.Equal(t, "lodash@4.17.4", view.Rows[1].Pkg)
	assert.Equal(t, "no", view.Rows[1].Fixable)
	assert.Equal(t, "SNYK-JS-QS-3153490", view.Rows[2].ID)
	assert.Equal(t, "low", view.Rows[2].Severity)
	assert.Equal(t, "qs@0.0.6", view.Rows[2].Pkg)
	assert.Equal(t, "yes", view.Rows[2].Fixable)
	assert.Equal(t, "3 unique vulns (4 paths) | 1 high 1 medium 1 low | 2 fixable", view.Summary)
}

func TestProjectSCA_empty(t *testing.T) {
	t.Parallel()

	view, err := toon.ProjectSCA(nil)
	require.NoError(t, err)
	assert.Empty(t, view.Rows)
	assert.Equal(t, "0 vulnerabilities found", view.Summary)
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

	view, err := toon.ProjectSCA([]testapi.TestResult{mock})
	require.NoError(t, err)

	require.Len(t, view.Rows, 1)
	assert.Equal(t, "lodash@4.17.4,4.17.10", view.Rows[0].Pkg)
	assert.Equal(t, "yes", view.Rows[0].Fixable)
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

	view, err := toon.ProjectSCA([]testapi.TestResult{mock})
	require.NoError(t, err)

	require.Len(t, view.Rows, 1)
	assert.Equal(t, "yes", view.Rows[0].Fixable)
	assert.Equal(t, "1 unique vulns (2 paths) | 1 medium | 1 fixable", view.Summary)
}

func TestProjectSecrets_fixture(t *testing.T) {
	t.Parallel()

	view, err := toon.ProjectSecrets(loadTestResults(t, "../testdata/ufm/secrets.toon.testresult.json"))
	require.NoError(t, err)

	assert.Len(t, view.Rows, 2)
	assert.Equal(t, "AWS Access Token", view.Rows[0].Rule)
	assert.Equal(t, "critical", view.Rows[0].Severity)
	assert.Equal(t, "app.py", view.Rows[0].File)
	assert.Equal(t, 1, view.Rows[0].Line)
	assert.Equal(t, "Slack Bot Token", view.Rows[1].Rule)
	assert.Equal(t, "high", view.Rows[1].Severity)
	assert.Equal(t, "app.py", view.Rows[1].File)
	assert.Equal(t, 5, view.Rows[1].Line)
	assert.Equal(t, "2 secrets | 1 critical 1 high", view.Summary)
}

func TestProjectSecrets_empty(t *testing.T) {
	t.Parallel()

	view, err := toon.ProjectSecrets(nil)
	require.NoError(t, err)
	assert.Empty(t, view.Rows)
	assert.Equal(t, "0 secrets found", view.Summary)
}

func TestProjectSecrets_specialCharactersPreserved(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mock := mocks.NewMockTestResult(ctrl)
	findings := []testapi.FindingData{
		*secretsFinding("rule,with\"comma\"", "src/with space.go", 42, "high"),
	}
	mock.EXPECT().Findings(gomock.Any()).Return(findings, true, nil)

	view, err := toon.ProjectSecrets([]testapi.TestResult{mock})
	require.NoError(t, err)

	require.Len(t, view.Rows, 1)
	assert.Equal(t, "rule,with\"comma\"", view.Rows[0].Rule)
	assert.Equal(t, "src/with space.go", view.Rows[0].File)
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
