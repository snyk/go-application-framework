package unified_presenters_test

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/presenters"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestJsonWriter(t *testing.T) {
	t.Run("strip whitespaces while writing", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writerUnderTest := presenters.NewJSONWriter(buffer, true)

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
		writerUnderTest := presenters.NewJSONWriter(buffer, false)

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

func TestUnifiedFindingPresenter_CliOutput(t *testing.T) {
	t.Run("license finding should not have risk score", func(t *testing.T) {
		// setup
		config := configuration.New()
		buffer := &bytes.Buffer{}

		problemID := uuid.New().String()
		licenseFinding := testapi.FindingData{
			Id:   util.Ptr(uuid.New()),
			Type: util.Ptr(testapi.Findings),
			Attributes: &testapi.FindingAttributes{
				Title: "GPL-3.0-only",
				Rating: testapi.Rating{
					Severity: testapi.Severity("medium"),
				},
				Problems: func() []testapi.Problem {
					var p testapi.Problem
					err := p.FromSnykLicenseProblem(testapi.SnykLicenseProblem{
						Id:      problemID,
						License: "license",
					})
					assert.NoError(t, err)
					return []testapi.Problem{p}
				}(),
			},
		}

		projectResult := &presenters.UnifiedProjectResult{
			Findings: []testapi.FindingData{licenseFinding},
			Summary: &json_schemas.TestSummary{
				SeverityOrderAsc: []string{"critical", "high", "medium", "low", "none"},
				Results: []json_schemas.TestSummaryResult{
					{
						Severity: "medium",
						Open:     1,
					},
				},
			},
		}

		presenter := presenters.NewUnifiedFindingsRenderer(
			[]*presenters.UnifiedProjectResult{projectResult},
			config,
			buffer,
		)

		// execute
		err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)

		// assert
		assert.NoError(t, err)
		output := buffer.String()
		assert.NotContains(t, output, "Risk Score:")
	})

	t.Run("vulnerability finding should have risk score", func(t *testing.T) {
		// setup
		config := configuration.New()
		buffer := &bytes.Buffer{}

		riskScore := uint16(780)
		vulnFinding := testapi.FindingData{
			Id:   util.Ptr(uuid.New()),
			Type: util.Ptr(testapi.Findings),
			Attributes: &testapi.FindingAttributes{
				Title: "High severity vulnerability",
				Risk: testapi.Risk{
					RiskScore: &testapi.RiskScore{
						Value: riskScore,
					},
				},
				Rating: testapi.Rating{
					Severity: testapi.Severity("high"),
				},
			},
		}

		projectResult := &presenters.UnifiedProjectResult{
			Findings: []testapi.FindingData{vulnFinding},
			Summary: &json_schemas.TestSummary{
				SeverityOrderAsc: []string{"critical", "high", "medium", "low", "none"},
				Results: []json_schemas.TestSummaryResult{
					{
						Severity: "high",
						Open:     1,
					},
				},
			},
		}

		presenter := presenters.NewUnifiedFindingsRenderer(
			[]*presenters.UnifiedProjectResult{projectResult},
			config,
			buffer,
		)

		// execute
		err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)

		// assert
		assert.NoError(t, err)
		output := buffer.String()
		assert.Contains(t, output, "Risk Score: 780")
	})
}
