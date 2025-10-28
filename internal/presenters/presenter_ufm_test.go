package presenters_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
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

	expectedSarifBytes, err := os.ReadFile("testdata/ufm/original_cli.sarif")
	assert.NoError(t, err)

	testResultBytes, err := os.ReadFile("testdata/ufm/testresult_cli.json")
	assert.NoError(t, err)

	testResult, err := ufm.NewSerializableTestResultFromBytes(testResultBytes)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(testResult))

	config := configuration.NewWithOpts()

	writer := &bytes.Buffer{}

	presenter := presenters.NewUfmRenderer(testResult, config, writer, presenters.UfmWithRuntimeInfo(ri))
	err = presenter.RenderTemplate(presenters.ApplicationSarifTemplatesUfm, presenters.ApplicationSarifMimeType)
	assert.NoError(t, err)

	validateSarifData(t, writer.Bytes())
	//	t.Log(writer.String())

	assert.JSONEq(t, string(expectedSarifBytes), writer.String())
}
