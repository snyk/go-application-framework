package presenters

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/stretchr/testify/assert"
	"github.com/xeipuuv/gojsonschema"
)

func validateSarifData(t *testing.T, data []byte) {
	t.Helper()

	sarifSchemaPath, err := filepath.Abs("../../internal/local_findings/source/sarif-schema-2.1.0.json")
	assert.NoError(t, err)

	sarifSchemaFile, err := os.Open(sarifSchemaPath)
	assert.NoError(t, err)

	sarifSchemaBytes, err := io.ReadAll(sarifSchemaFile)
	assert.NoError(t, err)

	sarifSchema := gojsonschema.NewBytesLoader(sarifSchemaBytes)
	assert.NotNil(t, sarifSchema)

	validationResult, err := gojsonschema.Validate(sarifSchema, gojsonschema.NewBytesLoader(data))
	assert.NoError(t, err)
	assert.NotNil(t, validationResult)
	if validationResult != nil {
		for _, validationError := range validationResult.Errors() {
			t.Log(validationError)
		}
		assert.True(t, validationResult.Valid(), "Sarif validation failed")
	}
}

func Test_UfmPresenter_Sarif(t *testing.T) {
	ri := runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.2.3"))
	ctlr := gomock.NewController(t)
	testResult := mocks.NewMockTestResult(ctlr)
	results := []testapi.TestResult{testResult}

	problem1 := testapi.Problem{}
	err := problem1.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:             "CVE-2024-12345",
		Source:         testapi.SnykVulnProblemSource("cve"),
		PackageName:    "package-name",
		PackageVersion: "package-version",
		PublishedAt:    time.Now(),
		Severity:       testapi.SeverityHigh,
	})
	assert.NoError(t, err)

	finding1 := testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			Title:       "Finding example high sev",
			FindingType: testapi.FindingTypeSca,
			Problems:    []testapi.Problem{problem1},
		},
	}

	testResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{finding1}, true, nil).AnyTimes()

	config := configuration.NewWithOpts()

	writer := &bytes.Buffer{}

	presenter := NewUfmRenderer(results, config, writer, UfmWithRuntimeInfo(ri))
	err = presenter.RenderTemplate(ApplicationSarifTemplatesUfm, ApplicationSarifMimeType)
	assert.NoError(t, err)

	validateSarifData(t, writer.Bytes())
	t.Log(writer.String())
}
