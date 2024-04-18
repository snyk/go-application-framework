package localworkflows

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"

	iMocks "github.com/snyk/go-application-framework/internal/mocks"
	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_Output_InitOutputWorkflow(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := InitOutputWorkflow(engine)
	assert.Nil(t, err)

	json := config.Get("json")
	assert.Equal(t, false, json)

	jsonFileOutput := config.Get("json-file-output")
	assert.Equal(t, "", jsonFileOutput)
}

func Test_Output_outputWorkflowEntryPoint(t *testing.T) {
	logger := &zerolog.Logger{}
	config := configuration.NewInMemory()

	// setup mocks
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	outputDestination := iMocks.NewMockOutputDestination(ctrl)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(logger).AnyTimes()

	payload := `
	{
		"schemaVersion": "1.2.0",
		"pkgManager": {
			"name": "npm"
		},
		"pkgs": [
			{
				"id": "goof@1.0.1",
				"info": {
					"name": "goof",
					"version": "1.0.1"
				}
			}
		],
		"graph": {
			"rootNodeId": "root-node",
			"nodes": [
				{
					"nodeId": "root-node",
					"pkgId": "goof@1.0.1",
					"deps": [
						{
							"nodeId": "adm-zip@0.4.7"
						},
						{
							"nodeId": "body-parser@1.9.0"
						}
					]
				}
			]
		}
	}`

	t.Run("should output to stdout by default for application/json", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, "application/json", []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(1)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should output to stdout by default for text/plain", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, "text/plain", []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(1)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should output to file when json-file-output is provided", func(t *testing.T) {
		expectedFileName := "test.json"
		config.Set("json-file-output", expectedFileName)
		defer config.Set("json-file-output", nil)

		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, "application/json", []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Remove(expectedFileName).Return(nil).Times(1)
		outputDestination.EXPECT().WriteFile(expectedFileName, []byte(payload), utils.FILEPERM_666).Return(nil).Times(1)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should output to (real) file when json-file-output is provided", func(t *testing.T) {
		expectedFileName := t.TempDir() + "test.json"
		config.Set("json-file-output", expectedFileName)
		defer config.Set("json-file-output", nil)
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, "application/json", []byte(payload))

		// mock assertions
		realOutputDestination := &utils.OutputDestinationImpl{}

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, realOutputDestination)
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
		assert.FileExists(t, expectedFileName)

		output, err = outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, realOutputDestination)
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should print unsupported mimeTypes that are string convertible", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, "hammer/head", payload)

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(1)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should reject unsupported mimeTypes", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, "hammer/head", workflowIdentifier) // re-using workflowIdentifier as data to have some non string data

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Equal(t, []workflow.Data{}, output)
		assert.Equal(t, "unsupported output type: hammer/head", err.Error())
	})

	t.Run("should reject test summary mimeType", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, content_type.TEST_SUMMARY, []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(0)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should reject versioned test summary mimeType", func(t *testing.T) {
		versionedTestSummaryContentType := content_type.TEST_SUMMARY + "; version=2024-04-10"
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, versionedTestSummaryContentType, []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(0)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should reject test summary mimeType and display known mimeType", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		testSummaryData := workflow.NewData(workflowIdentifier, content_type.TEST_SUMMARY, []byte(payload))
		textData := workflow.NewData(workflowIdentifier, "text/plain", []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(1)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{testSummaryData, textData}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should print human readable output for sarif data without ignored rules", func(t *testing.T) {
		input := sarif.SarifDocument{
			Runs: []sarif.Run{
				{
					Results: []sarif.Result{
						{Level: "error"},
						{Level: "warning"},
					},
				},
				{
					Results: []sarif.Result{
						{Level: "error"},
						{
							Level:        "error",
							Suppressions: make([]sarif.Suppression, 1),
							RuleID:       "rule1",
						},
					},
					Tool: sarif.Tool{
						Driver: sarif.Driver{
							Rules: []sarif.Rule{
								{
									ID:   "rule1",
									Name: "Ignored rule",
									ShortDescription: sarif.ShortDescription{
										Text: "Ignored rule",
									},
									Help: sarif.Help{
										Text: "Rule 1 help",
									},
									DefaultConfiguration: sarif.DefaultConfiguration{
										Level: "error",
									},
									Properties: sarif.RuleProperties{
										Tags: []string{"tag1", "tag2"},
										ShortDescription: sarif.ShortDescription{
											Text: "Rule 1 description",
										},
										Help: struct {
											Markdown string `json:"markdown"`
											Text     string `json:"text"`
										}{Markdown: "", Text: ""},
										Categories:         []string{},
										ExampleCommitFixes: []sarif.ExampleCommitFix{},
										Precision:          "",
										RepoDatasetSize:    0,
										Cwe:                []string{""},
									},
								},
							},
						},
					},
				},
				{
					Results: []sarif.Result{
						{Level: "note", Suppressions: make([]sarif.Suppression, 1)},
					},
				},
			},
		}

		rawSarif, err := json.Marshal(input)
		assert.Nil(t, err)

		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		sarifData := workflow.NewData(workflowIdentifier, content_type.SARIF_JSON, rawSarif)
		sarifData.SetContentLocation("/mypath")

		// mock assertions
		outputDestination.EXPECT().Println(gomock.Any()).Do(func(str string) {
			assert.Contains(t, str, "Total issues:   5")
			assert.NotContains(t, str, "Ignored rule")
		}).Times(1)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{sarifData}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should print human readable output for sarif data including ignored data", func(t *testing.T) {
		input := sarif.SarifDocument{
			Runs: []sarif.Run{
				{
					Results: []sarif.Result{
						{Level: "error"},
						{Level: "warning"},
					},
				},
				{
					Results: []sarif.Result{
						{Level: "error",
							RuleID: "openIssue",
						},
						{
							Level:        "error",
							Suppressions: make([]sarif.Suppression, 1),
							RuleID:       "rule1",
						},
					},
					Tool: sarif.Tool{
						Driver: sarif.Driver{
							Rules: []sarif.Rule{
								{
									ID:   "rule1",
									Name: "Ignored rule",
									ShortDescription: sarif.ShortDescription{
										Text: "Ignored rule",
									},
									Help: sarif.Help{
										Text: "Rule 1 help",
									},
									DefaultConfiguration: sarif.DefaultConfiguration{
										Level: "error",
									},
									Properties: sarif.RuleProperties{
										Tags: []string{"tag1", "tag2"},
										ShortDescription: sarif.ShortDescription{
											Text: "Rule 1 description",
										},
										Help: struct {
											Markdown string `json:"markdown"`
											Text     string `json:"text"`
										}{Markdown: "", Text: ""},
										Categories:         []string{},
										ExampleCommitFixes: []sarif.ExampleCommitFix{},
										Precision:          "",
										RepoDatasetSize:    0,
										Cwe:                []string{""},
									},
								},
								{
									ID:   "openIssue",
									Name: "This rule is open",
									ShortDescription: sarif.ShortDescription{
										Text: "This rule is open",
									},
									Help: sarif.Help{
										Text: "",
									},
									DefaultConfiguration: sarif.DefaultConfiguration{
										Level: "error",
									},
									Properties: sarif.RuleProperties{
										Tags: []string{"tag1", "tag2"},
										ShortDescription: sarif.ShortDescription{
											Text: "",
										},
										Help: struct {
											Markdown string `json:"markdown"`
											Text     string `json:"text"`
										}{Markdown: "", Text: ""},
										Categories:         []string{},
										ExampleCommitFixes: []sarif.ExampleCommitFix{},
										Precision:          "",
										RepoDatasetSize:    0,
										Cwe:                []string{""},
									},
								},
							},
						},
					},
				},
				{
					Results: []sarif.Result{
						{Level: "note", Suppressions: make([]sarif.Suppression, 1)},
					},
				},
			},
		}

		rawSarif, err := json.Marshal(input)
		assert.Nil(t, err)

		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		sarifData := workflow.NewData(workflowIdentifier, content_type.SARIF_JSON, rawSarif)
		sarifData.SetContentLocation("/mypath")

		// mock assertions
		outputDestination.EXPECT().Println(gomock.Any()).Do(func(str string) {
			assert.Contains(t, str, "Total issues:   5")
			assert.Contains(t, str, "Ignored rule")
			assert.Contains(t, str, "This rule is open")
		}).Times(1)

		config.Set(configuration.FLAG_INCLUDE_IGNORES, true)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{sarifData}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should print human readable output for sarif data only showing ignored data", func(t *testing.T) {
		input := sarif.SarifDocument{
			Runs: []sarif.Run{
				{
					Results: []sarif.Result{
						{Level: "error"},
						{Level: "warning"},
					},
				},
				{
					Results: []sarif.Result{
						{
							Level:  "error",
							RuleID: "openIssue",
						},
						{
							Level:        "error",
							Suppressions: make([]sarif.Suppression, 1),
							RuleID:       "rule1",
						},
					},
					Tool: sarif.Tool{
						Driver: sarif.Driver{
							Rules: []sarif.Rule{
								{
									ID:   "rule1",
									Name: "Ignored rule",
									ShortDescription: sarif.ShortDescription{
										Text: "Ignored rule",
									},
									Help: sarif.Help{
										Text: "Rule 1 help",
									},
									DefaultConfiguration: sarif.DefaultConfiguration{
										Level: "error",
									},
									Properties: sarif.RuleProperties{
										Tags: []string{"tag1", "tag2"},
										ShortDescription: sarif.ShortDescription{
											Text: "Rule 1 description",
										},
										Help: struct {
											Markdown string `json:"markdown"`
											Text     string `json:"text"`
										}{Markdown: "", Text: ""},
										Categories:         []string{},
										ExampleCommitFixes: []sarif.ExampleCommitFix{},
										Precision:          "",
										RepoDatasetSize:    0,
										Cwe:                []string{""},
									},
								},
								{
									ID:   "openIssue",
									Name: "This rule is open",
									ShortDescription: sarif.ShortDescription{
										Text: "This rule is open",
									},
									Help: sarif.Help{
										Text: "",
									},
									DefaultConfiguration: sarif.DefaultConfiguration{
										Level: "error",
									},
									Properties: sarif.RuleProperties{
										Tags: []string{"tag1", "tag2"},
										ShortDescription: sarif.ShortDescription{
											Text: "",
										},
										Help: struct {
											Markdown string `json:"markdown"`
											Text     string `json:"text"`
										}{Markdown: "", Text: ""},
										Categories:         []string{},
										ExampleCommitFixes: []sarif.ExampleCommitFix{},
										Precision:          "",
										RepoDatasetSize:    0,
										Cwe:                []string{""},
									},
								},
							},
						},
					},
				},
				{
					Results: []sarif.Result{
						{Level: "note", Suppressions: make([]sarif.Suppression, 1)},
					},
				},
			},
		}

		rawSarif, err := json.Marshal(input)
		assert.Nil(t, err)

		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		sarifData := workflow.NewData(workflowIdentifier, content_type.SARIF_JSON, rawSarif)
		sarifData.SetContentLocation("/mypath")

		// mock assertions
		outputDestination.EXPECT().Println(gomock.Any()).Do(func(str string) {
			assert.Contains(t, str, "Total issues:   5")
			assert.Contains(t, str, "Ignored rule")
			assert.NotContains(t, str, "This rule is open")
		}).Times(1)

		config.Set(configuration.FLAG_ONLY_IGNORES, true)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{sarifData}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})
}
