package localworkflows

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"

	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/local_workflows/output_workflow"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	sarif_utils "github.com/snyk/go-application-framework/pkg/utils/sarif"

	iMocks "github.com/snyk/go-application-framework/internal/mocks"
	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func getSortedSarifBytes(input []byte) ([]byte, error) {
	expectedSarif := &sarif.SarifDocument{}
	err := json.Unmarshal(input, expectedSarif)
	if err != nil {
		return nil, err
	}
	sortSarif(expectedSarif)

	prettyExpectedSarif, err := json.MarshalIndent(expectedSarif, "", "  ")
	if err != nil {
		return nil, err
	}

	return prettyExpectedSarif, nil
}

func sortSarif(sarifDoc *sarif.SarifDocument) {
	sort.Slice(sarifDoc.Runs, func(i, j int) bool {
		return sarifDoc.Runs[i].Tool.Driver.Name < sarifDoc.Runs[j].Tool.Driver.Name
	})
	for _, run := range sarifDoc.Runs {
		sort.Slice(run.Results, func(i, j int) bool {
			return run.Results[i].Fingerprints.Identity < run.Results[j].Fingerprints.Identity
		})
	}
}

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

func sarifToLocalFinding(t *testing.T, filename string, projectPath string) (localFinding *local_models.LocalFinding, err error) {
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

	summaryData := sarif_utils.CreateCodeSummary(&sarifDoc, projectPath)
	summaryBytes, err := json.Marshal(summaryData)
	assert.NoError(t, err)

	var tmp local_models.LocalFinding
	tmp, err = TransformSarifToLocalFindingModel(sarifBytes, summaryBytes)

	return &tmp, err
}

func getWorkflowDataFromLocalFinding(localFinding *local_models.LocalFinding) (workflow.Data, error) {
	localFindingBytes, err := json.Marshal(localFinding)
	if err != nil {
		return nil, err
	}

	return workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "LocalFinding"), content_type.LOCAL_FINDING_MODEL, localFindingBytes), nil
}

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
	writer := new(bytes.Buffer)

	// setup mocks
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	outputDestination := iMocks.NewMockOutputDestination(ctrl)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("Random Application Name"), runtimeinfo.WithVersion("1.0.0"))).AnyTimes()

	outputDestination.EXPECT().GetWriter().Return(writer).AnyTimes()

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

	t.Run("should not output anything for test summary mimeType", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, content_type.TEST_SUMMARY, []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(0)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, 1, len(output))
	})

	t.Run("should output local finding presentation for content_types.LOCAL_FINDING_MODEL", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		testfile := "testdata/sarif-snyk-goof-ignores.json"
		localFinding, err := sarifToLocalFinding(t, testfile, "/mypath")
		assert.NoError(t, err)
		localFindingBytes, err := json.Marshal(localFinding)
		assert.NoError(t, err)
		data := workflow.NewData(workflowIdentifier, content_type.LOCAL_FINDING_MODEL, localFindingBytes)
		wrongData := workflow.NewData(workflowIdentifier, content_type.TEST_SUMMARY, []byte("yolo"))
		writer.Reset()

		// execute
		_, err = outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data, wrongData}, outputDestination)
		assert.Nil(t, err)

		content := writer.String()
		// assert
		assert.Contains(t, content, "Total issues:   11")
		assert.Contains(t, content, "Project path:      /mypath")
	})

	t.Run("should output multiple results when there are multiple local findings models", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		writer.Reset()
		testfile1 := "testdata/sarif-snyk-goof-ignores.json"
		localFinding1, err := sarifToLocalFinding(t, testfile1, "/mypath")
		assert.NoError(t, err)
		localFindingBytes1, err := json.Marshal(localFinding1)
		assert.NoError(t, err)
		data1 := workflow.NewData(workflowIdentifier, content_type.LOCAL_FINDING_MODEL, localFindingBytes1)
		testfile2 := "testdata/sarif-juice-shop.json"
		localFinding2, err := sarifToLocalFinding(t, testfile2, "/juice-shop")
		assert.NoError(t, err)
		localFindingBytes2, err := json.Marshal(localFinding2)
		assert.NoError(t, err)
		data2 := workflow.NewData(workflowIdentifier, content_type.LOCAL_FINDING_MODEL, localFindingBytes2)
		// mock assertions
		outputDestination.EXPECT().GetWriter().Return(writer).AnyTimes()

		// execute
		_, err = outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data1, data2}, outputDestination)
		assert.Nil(t, err)

		content := writer.String()
		// assert
		assert.Contains(t, content, "Total issues:   11")
		assert.Contains(t, content, "Project path:      /mypath")
		assert.Contains(t, content, "Total issues:   278")
		assert.Contains(t, content, "Project path:      /juice-shop")
	})

	t.Run("should not output anything for versioned test summary mimeType", func(t *testing.T) {
		versionedTestSummaryContentType := content_type.TEST_SUMMARY + "; version=2024-04-10"
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, versionedTestSummaryContentType, []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(0)

		// execute
		output, err := outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, 1, len(output))
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
		assert.Equal(t, 1, len(output))
	})

	t.Run("should print valid sarif json output", func(t *testing.T) {
		expectedSarif := "testdata/sarif-snyk-goof-ignores.json"
		apiResponse := "testdata/sarif-snyk-goof-ignores.api.response.json"
		localFinding, err := sarifToLocalFinding(t, apiResponse, "/mypath")
		assert.Nil(t, err)

		resultMetaData := &scan.ResultMetaData{
			WebUiUrl:   "https://app.snyk.io/org/test/project/123",
			ProjectId:  "123",
			SnapshotId: "456",
		}
		local_models.TranslateMetadataToLocalFindingModel(resultMetaData, localFinding, config)

		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")

		localFindingBytes, err := json.Marshal(localFinding)
		assert.Nil(t, err)

		sarifData := workflow.NewData(workflowIdentifier, content_type.LOCAL_FINDING_MODEL, localFindingBytes)
		sarifData.SetContentLocation("/mypath")

		// mock assertions
		writer.Reset()

		config.Set(output_workflow.OUTPUT_CONFIG_KEY_SARIF, true)
		defer config.Set(output_workflow.OUTPUT_CONFIG_KEY_SARIF, nil)

		// execute
		_, err = outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{sarifData}, outputDestination)
		assert.NoError(t, err)

		// assert
		validateSarifData(t, writer.Bytes())

		expectedSarifFile, err := os.Open(expectedSarif)
		assert.NoError(t, err)

		expectedSarifBytes, err := io.ReadAll(expectedSarifFile)
		assert.NoError(t, err)

		prettyExpectedSarif, err := getSortedSarifBytes(expectedSarifBytes)
		assert.NoError(t, err)

		prettyActualSarif, err := getSortedSarifBytes(writer.Bytes())
		assert.NoError(t, err)

		expectedString := string(prettyExpectedSarif)
		actualSarifString := string(prettyActualSarif)

		require.JSONEq(t, expectedString, actualSarifString)
	})
}

func TestLocalFindingsHandling_renderFilesAndUI(t *testing.T) {
	logger := &zerolog.Logger{}
	config := configuration.NewWithOpts()

	fileWriters := []output_workflow.FileWriter{
		{
			NameConfigKey:     output_workflow.OUTPUT_CONFIG_KEY_SARIF_FILE,
			MimeType:          output_workflow.SARIF_MIME_TYPE,
			TemplateFiles:     output_workflow.ApplicationSarifTemplates,
			WriteEmptyContent: true,
		},
		{
			NameConfigKey:     output_workflow.OUTPUT_CONFIG_KEY_JSON_FILE,
			MimeType:          output_workflow.SARIF_MIME_TYPE,
			TemplateFiles:     output_workflow.ApplicationSarifTemplates,
			WriteEmptyContent: false,
		},
	}
	config.Set(output_workflow.OUTPUT_CONFIG_KEY_FILE_WRITERS, fileWriters)

	// setup mocks
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	outputDestination := iMocks.NewMockOutputDestination(ctrl)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.2.3"))).AnyTimes()

	byteBuffer := &bytes.Buffer{}
	outputDestination.EXPECT().GetWriter().Return(byteBuffer).AnyTimes()

	expectedSarifFile := filepath.Join(t.TempDir(), "TestLocalFindingsHandling.sarif")
	expectedJsonFile := filepath.Join(t.TempDir(), "TestLocalFindingsHandling.json")
	config.Set(output_workflow.OUTPUT_CONFIG_KEY_SARIF_FILE, expectedSarifFile)
	config.Set(output_workflow.OUTPUT_CONFIG_KEY_JSON_FILE, expectedJsonFile)
	config.Set(configuration.MAX_THREADS, 10)

	testfile := "testdata/sarif-snyk-goof-ignores.json"

	finding, err := sarifToLocalFinding(t, testfile, "")
	assert.NoError(t, err)

	findingData, err := getWorkflowDataFromLocalFinding(finding)
	assert.NoError(t, err)

	randomData1 := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "random"), content_type.SARIF_JSON, []byte{})
	randomData2 := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "random"), "plain", []byte{})
	input := []workflow.Data{randomData1, findingData, randomData2}

	// invoking method under test
	actualRemainingData, err := output_workflow.HandleContentTypeFindingsModel(input, invocationContextMock, outputDestination)
	assert.NoError(t, err)
	assert.NotNil(t, actualRemainingData)

	expectedRemainingData := []workflow.Data{randomData1, randomData2}
	assert.Equal(t, expectedRemainingData, actualRemainingData)

	dataFromJsonFile, err := os.ReadFile(expectedJsonFile)
	assert.NoError(t, err)
	dataFromSarifFile, err := os.ReadFile(expectedSarifFile)
	assert.NoError(t, err)
	assert.NotEmpty(t, dataFromSarifFile)
	assert.Equal(t, dataFromSarifFile, dataFromJsonFile)

	dataFromBuffer := byteBuffer.Bytes()
	assert.NotEmpty(t, dataFromBuffer)

	validateSarifData(t, dataFromSarifFile)
}

func BenchmarkTransformationAndOutputWorkflow(b *testing.B) {
	t := &testing.T{}
	logger := &zerolog.Logger{}
	config := configuration.NewWithOpts()
	writer := new(bytes.Buffer)

	// setup mocks
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	outputDestination := iMocks.NewMockOutputDestination(ctrl)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("SnykCode"), runtimeinfo.WithVersion("1.0.0"))).AnyTimes()
	outputDestination.EXPECT().GetWriter().Return(writer).AnyTimes()

	config.Set(output_workflow.OUTPUT_CONFIG_KEY_SARIF, true)
	testfile := "testdata/10000Findings.json"

	b.Run("sarif to localFindings transformer", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			start := time.Now()
			var memStart runtime.MemStats
			var memEnd runtime.MemStats
			runtime.ReadMemStats(&memStart)

			writer.Reset()
			localFinding, err := sarifToLocalFinding(t, testfile, "/mypath")
			assert.Nil(t, err)

			workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")

			localFindingBytes, err := json.Marshal(localFinding)
			assert.Nil(t, err)

			sarifData := workflow.NewData(workflowIdentifier, content_type.LOCAL_FINDING_MODEL, localFindingBytes)
			sarifData.SetContentLocation("/mypath")

			// execute
			_, err = outputWorkflowEntryPoint(invocationContextMock, []workflow.Data{sarifData}, outputDestination)
			assert.NoError(t, err)

			runtime.ReadMemStats(&memEnd)
			duration := time.Since(start)
			b.Logf("Used Memory: %d [MB]", (memEnd.TotalAlloc-memStart.TotalAlloc)/1024/1024)
			b.Logf("Duration: %s", duration)

			// assert
			validateSarifData(t, writer.Bytes())

			if duration > 10*time.Second {
				b.Fatalf("native transformation took too long: %s", duration)
			}
		}
	})
}

func TestJsonWriteToFile(t *testing.T) {
	i := 0
	logger := zerolog.Nop()
	outputDi := utils.NewOutputDestination()
	fileName := filepath.Join(t.TempDir(), "not-existing", "file.json")
	rawData := []byte("hello world")
	data := []workflow.Data{
		workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output"), "content-type", rawData),
	}

	assert.NoFileExists(t, fileName)
	err := jsonWriteToFile(&logger, data, i, rawData, fileName, outputDi)
	assert.NoError(t, err)
	assert.FileExists(t, fileName)
}
