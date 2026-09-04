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
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/utils"
	sarif_utils "github.com/snyk/go-application-framework/pkg/utils/sarif"
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

	summaryData := sarif_utils.CreateCodeSummary(&sarifDoc, "/path/to/project")
	summaryBytes, err := json.Marshal(summaryData)
	assert.NoError(t, err)

	tmp, err := localworkflows.TransformSarifToLocalFindingModel(sarifBytes, summaryBytes)
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

	p := presenters.NewLocalFindingsRenderer(
		[]*local_models.LocalFinding{localFindingDoc},
		config,
		writer,
	)

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
		[]*local_models.LocalFinding{input},
		config,
		writer,
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
		[]*local_models.LocalFinding{input},
		config,
		writer,
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
		[]*local_models.LocalFinding{input},
		config,
		writer,
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
		[]*local_models.LocalFinding{input},
		config,
		writer,
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
	config.Set(configuration.FLAG_INCLUDE_IGNORES, false)
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		[]*local_models.LocalFinding{input},
		config,
		writer,
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
	config.Set(configuration.FLAG_INCLUDE_IGNORES, true)
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		[]*local_models.LocalFinding{input},
		config,
		writer,
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)

	require.Contains(t, result, "Ignored Issues")
	require.Contains(t, result, " ! [MEDIUM] Cleartext Transmission of Sensitive Information [ IGNORED ]")
	require.Contains(t, result, "src/main.ts, line 58")
	require.Contains(t, result, "Ignores are currently managed in the Snyk Web UI.")
	require.NotContains(t, result, "Empty ignore issues state")
	require.NotContains(t, result, "To view ignored and open issues, use the --include-ignores option.pre")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_WithStatusPropertyAccepted(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/with-ignores-with-status-accepted.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	config.Set(configuration.FLAG_INCLUDE_IGNORES, true)
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		[]*local_models.LocalFinding{input},
		config,
		writer,
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)

	require.Contains(t, result, "Ignored Issues")
	require.Contains(t, result, "! [MEDIUM] Cleartext Transmission of Sensitive Information [ IGNORED ]")
	require.Contains(t, result, "src/main.ts, line 58")
	require.Contains(t, result, "Ignores are currently managed in the Snyk Web UI.")
	require.NotContains(t, result, "Empty ignore issues state")
	require.NotContains(t, result, "To view ignored and open issues, use the --include-ignores option.pre")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_WithStatusPropertyUnderReview(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/with-ignores-with-status-underReview.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	config.Set(configuration.FLAG_INCLUDE_IGNORES, true)
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		[]*local_models.LocalFinding{input},
		config,
		writer,
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)

	require.Contains(t, result, "! [MEDIUM] Cleartext Transmission of Sensitive Information [ PENDING IGNORE... ]")
	require.NotContains(t, result, "[ IGNORED ]")
	require.Contains(t, result, "There are no ignored issues")
	require.Contains(t, result, local_models.DefaultSuppressionExpiration)

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_WithStatusPropertyRejected(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/with-ignores-with-status-rejected.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	config.Set(configuration.FLAG_INCLUDE_IGNORES, true)
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		[]*local_models.LocalFinding{input},
		config,
		writer,
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)

	require.NotContains(t, result, "[ IGNORED ]")
	require.Contains(t, result, "There are no ignored issues")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_IncludeIgnoredEmpty(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/3-low-issues.json")
	require.Nil(t, err)

	expectedUrl := "https://this.url.is.exptected"
	input.Links = make(map[string]string)
	input.Links[local_models.LINKS_KEY_REPORT] = expectedUrl

	lipgloss.SetColorProfile(termenv.Ascii)

	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION_SLUG, "test-org")
	config.Set(configuration.FLAG_INCLUDE_IGNORES, true)
	writer := new(bytes.Buffer)

	p := presenters.NewLocalFindingsRenderer(
		[]*local_models.LocalFinding{input},
		config,
		writer,
	)

	err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	result := writer.String()

	require.Nil(t, err)
	require.NotContains(t, result, "[ IGNORED ]")
	require.Contains(t, result, "There are no ignored issues")
	require.Contains(t, result, expectedUrl)

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
		[]*local_models.LocalFinding{input},
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

	t.Run("custom template file (with whitespaces)", func(t *testing.T) {
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

	t.Run("custom template file (without whitespaces)", func(t *testing.T) {
		writer.Reset()
		config.Set(presenters.CONFIG_JSON_STRIP_WHITESPACES, true)

		err = p.RenderTemplate([]string{"testdata/custom_template.tmpl"}, "application/json")
		assert.NoError(t, err)

		expected := `{"findings" :["Use of Hardcoded Credentials","Use of Hardcoded Credentials","Use of Password Hash With Insufficient Computational Effort"]}`

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

func TestJsonWriter(t *testing.T) {
	t.Run("strip whitespaces while writing", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writerUnderTest := presenters.NewJsonWriter(buffer, true)

		input := []byte(`{
	"name": "myName",
	"address": "myAddr"
}`)

		expected := `{"name": "myName","address": "myAddr"}`

		bytesWritten, err := writerUnderTest.Write(input)
		assert.NoError(t, err)
		assert.Equal(t, len(input), bytesWritten)
		assert.Equal(t, expected, buffer.String())
	})

	t.Run("Don't strip whitespaces while writing", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writerUnderTest := presenters.NewJsonWriter(buffer, false)

		input := []byte(`{
	"name": "myName",
    "address": "myAddr"
}`)

		bytesWritten, err := writerUnderTest.Write(input)
		assert.NoError(t, err)
		assert.Equal(t, len(input), bytesWritten)
		assert.Equal(t, input, buffer.Bytes())
	})
}

func TestPresenterLocalFinding_ComponentReviewDetails(t *testing.T) {
	tests := []struct {
		name               string
		reviewedBy         *local_models.TypesReviewer
		reviewedOn         *string
		expectedReviewedBy *string
		expectedReviewedOn *string
	}{
		{
			name:               "name and email renders the name only",
			reviewedBy:         &local_models.TypesReviewer{Name: "Jane Reviewer", Email: utils.Ptr("jane@example.com")},
			reviewedOn:         utils.Ptr("2023-02-02T10:30:00Z"),
			expectedReviewedBy: utils.Ptr("Reviewed by: Jane Reviewer"),
			expectedReviewedOn: utils.Ptr("Reviewed on: February 02, 2023"),
		},
		{
			name:               "name only, nil email",
			reviewedBy:         &local_models.TypesReviewer{Name: "John Reviewer", Email: nil},
			expectedReviewedBy: utils.Ptr("Reviewed by: John Reviewer"),
		},
		{
			name:               "unparsable reviewedOn is rendered verbatim",
			reviewedOn:         utils.Ptr("not-a-timestamp"),
			expectedReviewedOn: utils.Ptr("Reviewed on: not-a-timestamp"),
		},
		{
			name: "nil reviewedBy and reviewedOn",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input, err := sarifToLocalFinding(t, "testdata/with-ignores-with-status-accepted.json")
			require.NoError(t, err)

			suppressedCount := 0
			for i := range input.Findings {
				suppression := input.Findings[i].Attributes.Suppression
				if suppression == nil || suppression.Details == nil {
					continue
				}
				suppression.Details.ReviewedBy = tc.reviewedBy
				suppression.Details.ReviewedOn = tc.reviewedOn
				suppressedCount++
			}
			require.Positive(t, suppressedCount, "test fixture must contain suppressed findings with details")

			lipgloss.SetColorProfile(termenv.Ascii)
			config := configuration.NewInMemory()
			config.Set(configuration.ORGANIZATION_SLUG, "test-org")
			config.Set(configuration.FLAG_INCLUDE_IGNORES, true)
			writer := new(bytes.Buffer)

			p := presenters.NewLocalFindingsRenderer(
				[]*local_models.LocalFinding{input},
				config,
				writer,
			)

			err = p.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
			require.NoError(t, err)

			result := writer.String()
			require.Contains(t, result, "Ignored Issues")

			if tc.expectedReviewedBy != nil {
				assert.Contains(t, result, *tc.expectedReviewedBy)
			} else {
				assert.NotContains(t, result, "Reviewed by:")
			}

			if tc.expectedReviewedOn != nil {
				assert.Contains(t, result, *tc.expectedReviewedOn)
			} else {
				assert.NotContains(t, result, "Reviewed on:")
			}

			if tc.reviewedBy != nil && tc.reviewedBy.Email != nil {
				assert.NotContains(t, result, *tc.reviewedBy.Email, "the plain text output must not expose the reviewer email")
			}
		})
	}
}

func TestPresenterLocalFinding_SarifReviewDetails(t *testing.T) {
	type sarifReviewedBy struct {
		Name  *string `json:"name"`
		Email *string `json:"email"`
	}
	type sarifSuppressionProperties struct {
		ReviewedBy *sarifReviewedBy `json:"reviewedBy"`
		ReviewedOn *string          `json:"reviewedOn"`
	}
	type sarifSuppression struct {
		Properties *sarifSuppressionProperties `json:"properties"`
	}
	type sarifResult struct {
		Suppressions []sarifSuppression `json:"suppressions"`
	}
	type sarifRun struct {
		Results []sarifResult `json:"results"`
	}
	type sarifDocument struct {
		Runs []sarifRun `json:"runs"`
	}

	tests := []struct {
		name               string
		reviewedBy         *local_models.TypesReviewer
		reviewedOn         *string
		expectedName       *string
		expectedEmail      *string
		expectedReviewedOn *string
	}{
		{
			name:               "name, email and reviewedOn",
			reviewedBy:         &local_models.TypesReviewer{Name: "Jane Reviewer", Email: utils.Ptr("jane@example.com")},
			reviewedOn:         utils.Ptr("2023-02-02T10:30:00Z"),
			expectedName:       utils.Ptr("Jane Reviewer"),
			expectedEmail:      utils.Ptr("jane@example.com"),
			expectedReviewedOn: utils.Ptr("2023-02-02T10:30:00Z"),
		},
		{
			name:          "name only, nil email",
			reviewedBy:    &local_models.TypesReviewer{Name: "John Reviewer", Email: nil},
			expectedName:  utils.Ptr("John Reviewer"),
			expectedEmail: utils.Ptr(""),
		},
		{
			name:          "name with special characters",
			reviewedBy:    &local_models.TypesReviewer{Name: `O'Brien "The Reviewer"`, Email: utils.Ptr("obrien@example.com")},
			expectedName:  utils.Ptr(`O'Brien "The Reviewer"`),
			expectedEmail: utils.Ptr("obrien@example.com"),
		},
		{
			name:          "empty name",
			reviewedBy:    &local_models.TypesReviewer{Name: "", Email: utils.Ptr("empty@example.com")},
			expectedName:  utils.Ptr(""),
			expectedEmail: utils.Ptr("empty@example.com"),
		},
		{
			name:       "nil reviewedBy and reviewedOn",
			reviewedBy: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input, err := sarifToLocalFinding(t, "testdata/with-ignores-with-status-accepted.json")
			require.NoError(t, err)

			suppressedCount := 0
			for i := range input.Findings {
				suppression := input.Findings[i].Attributes.Suppression
				if suppression == nil || suppression.Details == nil {
					continue
				}
				suppression.Details.ReviewedBy = tc.reviewedBy
				suppression.Details.ReviewedOn = tc.reviewedOn
				suppressedCount++
			}
			require.Positive(t, suppressedCount, "test fixture must contain suppressed findings with details")

			config := configuration.NewInMemory()
			config.Set(configuration.ORGANIZATION_SLUG, "test-org")
			writer := new(bytes.Buffer)

			p := presenters.NewLocalFindingsRenderer(
				[]*local_models.LocalFinding{input},
				config,
				writer,
			)

			err = p.RenderTemplate(presenters.ApplicationSarifTemplates, presenters.ApplicationSarifMimeType)
			require.NoError(t, err)

			output := writer.Bytes()
			require.True(t, json.Valid(output), "rendered SARIF must be valid JSON: %s", output)

			var doc sarifDocument
			require.NoError(t, json.Unmarshal(output, &doc))
			require.NotEmpty(t, doc.Runs)

			checked := 0
			for _, run := range doc.Runs {
				for _, result := range run.Results {
					for _, suppression := range result.Suppressions {
						require.NotNil(t, suppression.Properties)
						checked++

						if tc.expectedReviewedOn == nil {
							assert.Nil(t, suppression.Properties.ReviewedOn)
						} else {
							require.NotNil(t, suppression.Properties.ReviewedOn)
							assert.Equal(t, *tc.expectedReviewedOn, *suppression.Properties.ReviewedOn)
						}

						if tc.expectedName == nil {
							assert.Nil(t, suppression.Properties.ReviewedBy)
							continue
						}
						require.NotNil(t, suppression.Properties.ReviewedBy)
						require.NotNil(t, suppression.Properties.ReviewedBy.Name)
						assert.Equal(t, *tc.expectedName, *suppression.Properties.ReviewedBy.Name)
						require.NotNil(t, suppression.Properties.ReviewedBy.Email)
						require.NotNil(t, tc.expectedEmail)
						assert.Equal(t, *tc.expectedEmail, *suppression.Properties.ReviewedBy.Email)
					}
				}
			}
			require.Positive(t, checked, "rendered SARIF must contain suppressions")
		})
	}
}

func TestSarifAutomationDetailsId(t *testing.T) {
	type SarifOutput struct {
		Runs []struct {
			AutomationDetails struct {
				Id string `json:"id"`
			} `json:"automationDetails"`
		} `json:"runs"`
	}

	input, err := sarifToLocalFinding(t, "testdata/3-low-issues.json")
	require.Nil(t, err)

	t.Run("with project name", func(t *testing.T) {
		projectName := `"test" project`
		config := configuration.New()
		config.Set("project-name", projectName)
		writer := new(bytes.Buffer)
		p := presenters.NewLocalFindingsRenderer(
			[]*local_models.LocalFinding{input},
			config,
			writer,
		)

		err = p.RenderTemplate(presenters.ApplicationSarifTemplates, presenters.ApplicationSarifMimeType)
		require.NoError(t, err)

		var sarifOutput SarifOutput
		err = json.Unmarshal(writer.Bytes(), &sarifOutput)
		require.Nil(t, err)
		require.Regexp(t, `Snyk/Code/`+projectName+`/.*`, sarifOutput.Runs[0].AutomationDetails.Id)
	})

	t.Run("without project name", func(t *testing.T) {
		config := configuration.New()
		writer := new(bytes.Buffer)
		p := presenters.NewLocalFindingsRenderer(
			[]*local_models.LocalFinding{input},
			config,
			writer,
		)

		err = p.RenderTemplate(presenters.ApplicationSarifTemplates, presenters.ApplicationSarifMimeType)
		require.Nil(t, err)

		var sarifOutput SarifOutput
		err = json.Unmarshal(writer.Bytes(), &sarifOutput)
		require.Nil(t, err)
		require.Regexp(t, "Snyk/Code/.*", sarifOutput.Runs[0].AutomationDetails.Id)
	})
}
