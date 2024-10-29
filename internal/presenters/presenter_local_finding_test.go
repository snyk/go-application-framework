package presenters_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
	"text/template"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/muesli/termenv"
	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters"
	sarif_utils "github.com/snyk/go-application-framework/internal/utils/sarif"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

func sarifToLocalFinding(t *testing.T, filename string) (localFinding *local_models.LocalFinding, err error) {
	t.Helper()
	jsonFile, err := os.Open("./" + filename)
	if err != nil {
		t.Errorf("Failed to load json")
	}

	defer func(jsonFile *os.File) {
		jsonErr := jsonFile.Close()
		assert.NoError(t, jsonErr)
	}(jsonFile)
	sarifBytes, err := io.ReadAll(jsonFile)
	assert.NoError(t, err)

	// Read sarif file again for summary
	var sarifDoc sarif.SarifDocument

	err = json.Unmarshal(sarifBytes, &sarifDoc)
	assert.NoError(t, err)

	summaryData := sarif_utils.CreateCodeSummary(&sarifDoc)
	summaryBytes, err := json.Marshal(summaryData)
	assert.NoError(t, err)

	tmp, err := localworkflows.TransformToLocalFindingModel(sarifBytes, summaryBytes)
	return &tmp, err
}

func TestPresenterLocalFinding_NoIssues(t *testing.T) {
	fd, err := os.Open("testdata/local-findings-empty.json")
	require.NoError(t, err)

	var localFindingDoc *local_models.LocalFinding
	err = json.NewDecoder(fd).Decode(&localFindingDoc)
	require.NoError(t, err)

	scannedPath := "/path/to/project"
	lipgloss.SetColorProfile(termenv.Ascii)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(localFindingDoc,
		config,
		writer,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath(scannedPath))

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.NoError(t, err)
	assert.Contains(t, result, "Testing "+scannedPath)
	assert.NotContains(t, result, "Ignored issues")
	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_LowIssues(t *testing.T) {
	// Convert our sarif into localfindings
	input, err := sarifToLocalFinding(t, "testdata/3-low-issues.json")
	require.NoError(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		input,
		config,
		writer,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.NoError(t, err)
	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_MediumHighIssues(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		input,
		config,
		writer,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)

	require.Contains(t, result, "[ 0 HIGH  0 MEDIUM  0 LOW ]")
	require.Contains(t, result, "[ 4 HIGH  5 MEDIUM  0 LOW ]")
	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_MediumHighIssuesWithColor(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.TrueColor)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		input,
		config,
		writer,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)
	require.NotContains(t, result, "You are currently viewing results with --severity-threshold=high applied")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_MediumHighIssuesWithColorLight(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.TrueColor)
	lipgloss.SetHasDarkBackground(false)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		input,
		config,
		writer,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)
	require.NotContains(t, result, "You are currently viewing results with --severity-threshold=high applied")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_DefaultHideIgnored(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/with-ignores.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		input,
		config,
		writer,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
		presenters.WithLocalFindingsIgnoredIssues(false),
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)
	require.NotContains(t, result, "src/main.ts, line 58")
	require.NotContains(t, result, "Ignored Issues")
}

func TestPresenterLocalFinding_IncludeIgnored(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/with-ignores.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		input,
		config,
		writer,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
		presenters.WithLocalFindingsIgnoredIssues(true),
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)

	require.Contains(t, result, "Ignored Issues")
	require.Contains(t, result, "[ IGNORED ] [MEDIUM]")
	require.Contains(t, result, "src/main.ts, line 58")
	require.Contains(t, result, "Ignores are currently managed in the Snyk Web UI.")
	require.NotContains(t, result, "Empty ignore issues state")
	require.NotContains(t, result, "To view ignored and open issues, use the --include-ignores option.pre")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_IncludeIgnoredEmpty(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/3-low-issues.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)

	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		input,
		config,
		writer,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
		presenters.WithLocalFindingsIgnoredIssues(true),
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)
	require.NotContains(t, result, "[ IGNORED ]")
	require.Contains(t, result, "There are no ignored issues")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_CustomTemplateFiles(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/3-low-issues.json")
	require.Nil(t, err)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION, "org-id1267361872673627")
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	writer := new(bytes.Buffer)
	p := presenters.NewLocalFindingsRenderer(
		input,
		config,
		writer,
	)

	t.Run("no template files", func(t *testing.T) {
		err = p.RenderTemplate([]string{}, presenters.DefaultMimeType)
		assert.Error(t, err)
	})

	t.Run("not existing template file", func(t *testing.T) {
		err = p.RenderTemplate([]string{"notexstingfile.tmpl"}, presenters.DefaultMimeType)
		assert.Error(t, err)
	})

	t.Run("unknown mimetype", func(t *testing.T) {
		err = p.RenderTemplate([]string{"testdata/custom_template_html.tmpl"}, "application/me")
		assert.NoError(t, err)
	})

	t.Run("custom template file missing main", func(t *testing.T) {
		err = p.RenderTemplate([]string{"testdata/custom_template_no_main.tmpl"}, "application/json")
		assert.Error(t, err)
	})

	t.Run("custom template file", func(t *testing.T) {
		writer.Reset()

		err = p.RenderTemplate([]string{"testdata/custom_template.tmpl"}, "application/json")
		assert.NoError(t, err)

		expected := `{
    "findings" :
    [
        "Use of Hardcoded Credentials",
        "Use of Hardcoded Credentials",
        "Use of Password Hash With Insufficient Computational Effort"
    ]
}`

		actual := writer.String()
		assert.Equal(t, expected, actual)
	})
}

func TestPresenterLocalFinding_RegisterMimeType(t *testing.T) {
	config := configuration.NewInMemory()
	writer := new(bytes.Buffer)
	p := presenters.NewLocalFindingsRenderer(nil, config, writer)

	t.Run("try registering existing type", func(t *testing.T) {
		err := p.RegisterMimeType(presenters.DefaultMimeType, func() (*template.Template, template.FuncMap, error) {
			return nil, nil, nil
		})
		assert.Error(t, err)
	})

	t.Run("try registering a new type", func(t *testing.T) {
		err := p.RegisterMimeType("mymime", func() (*template.Template, template.FuncMap, error) {
			return nil, nil, nil
		})
		assert.NoError(t, err)
	})
}
