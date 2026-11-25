package output_workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	pkgMocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

//nolint:unparam // path should be kept configurable
func loadTestResults(t *testing.T, path string) []testapi.TestResult {
	t.Helper()
	testResultBytes, err := os.ReadFile(path)
	assert.NoError(t, err)
	testResult, err := ufm.NewSerializableTestResultFromBytes(testResultBytes)
	assert.NoError(t, err)
	return testResult
}

func Test_getTotalNumberOfUnifiedFindings(t *testing.T) {
	t.Run("nil results", func(t *testing.T) {
		var results []testapi.TestResult
		count := getTotalNumberOfUnifiedFindings(results)
		assert.Equal(t, 0, count)
	})

	t.Run("count from real test data", func(t *testing.T) {
		results := loadTestResults(t, "../../../internal/presenters/testdata/ufm/secrets.testresult.json")
		count := getTotalNumberOfUnifiedFindings(results)
		assert.Greater(t, count, 0)
	})
}

type nopCloser struct {
	writer io.Writer
}

func (n *nopCloser) Write(p []byte) (int, error) {
	return n.writer.Write(p)
}

func (n *nopCloser) Close() error {
	return nil
}

type testWriterMap struct {
	writers map[string][]*WriterEntry
}

func (w *testWriterMap) PopWritersByMimetype(mimeType string) []*WriterEntry {
	writers := w.writers[mimeType]
	delete(w.writers, mimeType)
	return writers
}

func (w *testWriterMap) Length() int {
	count := 0
	for _, writers := range w.writers {
		count += len(writers)
	}
	return count
}

func (w *testWriterMap) AvailableMimetypes() []string {
	keys := make([]string, 0, len(w.writers))
	for k := range w.writers {
		keys = append(keys, k)
	}
	return keys
}

func (w *testWriterMap) String() string {
	return "testWriterMap"
}

func Test_HandleContentTypeUnifiedModel(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.NewWithOpts()

	t.Run("returns nil when no test results in input", func(t *testing.T) {
		mockCtl := gomock.NewController(t)
		defer mockCtl.Finish()

		ctx := pkgMocks.NewMockInvocationContext(mockCtl)
		ctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()

		input := []workflow.Data{}
		writers := &testWriterMap{writers: map[string][]*WriterEntry{}}

		remaining, err := HandleContentTypeUnifiedModel(input, ctx, writers)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
	})

	t.Run("returns error when rendering fails with invalid template", func(t *testing.T) {
		mockCtl := gomock.NewController(t)
		defer mockCtl.Finish()

		ctx := pkgMocks.NewMockInvocationContext(mockCtl)
		ctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()
		ctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
		ctx.EXPECT().Context().Return(t.Context()).AnyTimes()

		results := loadTestResults(t, "../../../internal/presenters/testdata/ufm/secrets.testresult.json")
		workflowData := ufm.CreateWorkflowDataFromTestResults(workflow.NewWorkflowIdentifier("test"), results)
		input := []workflow.Data{workflowData}

		buffer := &bytes.Buffer{}
		writers := &testWriterMap{
			writers: map[string][]*WriterEntry{
				DEFAULT_MIME_TYPE: {{
					writer:          &nopCloser{writer: buffer},
					mimeType:        DEFAULT_MIME_TYPE,
					templates:       []string{"invalid_template.tmpl"},
					renderEmptyData: true,
				}},
			},
		}

		remaining, err := HandleContentTypeUnifiedModel(input, ctx, writers)
		assert.Error(t, err)
		assert.NotNil(t, remaining)
	})

	t.Run("collects multiple errors from parallel goroutines", func(t *testing.T) {
		mockCtl := gomock.NewController(t)
		defer mockCtl.Finish()

		ctx := pkgMocks.NewMockInvocationContext(mockCtl)
		ctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()
		ctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
		ctx.EXPECT().Context().Return(t.Context()).AnyTimes()

		results := loadTestResults(t, "../../../internal/presenters/testdata/ufm/secrets.testresult.json")
		workflowData := ufm.CreateWorkflowDataFromTestResults(workflow.NewWorkflowIdentifier("test"), results)
		input := []workflow.Data{workflowData}

		buffer1 := &bytes.Buffer{}
		buffer2 := &bytes.Buffer{}
		writers := &testWriterMap{
			writers: map[string][]*WriterEntry{
				DEFAULT_MIME_TYPE: {{
					writer:          &nopCloser{writer: buffer1},
					mimeType:        DEFAULT_MIME_TYPE,
					templates:       []string{"invalid_template1.tmpl"},
					renderEmptyData: true,
					name:            "writer1",
				}},
				SARIF_MIME_TYPE: {{
					writer:          &nopCloser{writer: buffer2},
					mimeType:        SARIF_MIME_TYPE,
					templates:       []string{"invalid_template2.tmpl"},
					renderEmptyData: true,
					name:            "writer2",
				}},
			},
		}

		remaining, err := HandleContentTypeUnifiedModel(input, ctx, writers)
		assert.Error(t, err)
		assert.NotNil(t, remaining)

		// Verify that errors.Join was used to collect errors from both goroutines
		var joinedErrs interface{ Unwrap() []error }
		if errors.As(err, &joinedErrs) {
			unwrapped := joinedErrs.Unwrap()
			assert.Equal(t, 2, len(unwrapped))
		}
	})

	t.Run("html and sarif file outputs are produced in the same run", func(t *testing.T) {
		mockCtl := gomock.NewController(t)
		defer mockCtl.Finish()

		fileConfig := configuration.NewWithOpts()
		expectedHTMLFile := filepath.Join(t.TempDir(), "report.html")
		expectedSarifFile := filepath.Join(t.TempDir(), "report.sarif")
		fileConfig.Set(OUTPUT_CONFIG_KEY_HTML_FILE, expectedHTMLFile)
		fileConfig.Set(OUTPUT_CONFIG_KEY_SARIF_FILE, expectedSarifFile)
		fileConfig.Set(configuration.MAX_THREADS, 10)

		ctx := pkgMocks.NewMockInvocationContext(mockCtl)
		ctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		ctx.EXPECT().GetConfiguration().Return(fileConfig).AnyTimes()
		ctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.1301.0"))).AnyTimes()
		ctx.EXPECT().Context().Return(t.Context()).AnyTimes()

		results := loadTestResults(t, "../../../internal/presenters/testdata/ufm/secrets.testresult.json")
		workflowData := ufm.CreateWorkflowDataFromTestResults(workflow.NewWorkflowIdentifier("test"), results)
		input := []workflow.Data{workflowData}

		writers := GetWritersFromConfiguration(fileConfig, &stubOutputDestination{})

		remaining, err := HandleContentTypeUnifiedModel(input, ctx, writers)
		assert.NoError(t, err)
		assert.NotNil(t, remaining)

		htmlBytes, err := os.ReadFile(expectedHTMLFile)
		assert.NoError(t, err, "HTML file should have been written")
		assert.Contains(t, strings.ToLower(string(htmlBytes)), "<!doctype html>")

		sarifBytes, err := os.ReadFile(expectedSarifFile)
		assert.NoError(t, err, "SARIF file should have been written")
		assert.Contains(t, string(sarifBytes), "\"version\": \"2.1.0\"")
	})

	t.Run("html flag renders HTML to the default stdout writer", func(t *testing.T) {
		mockCtl := gomock.NewController(t)
		defer mockCtl.Finish()

		stdoutConfig := configuration.NewWithOpts()
		stdoutConfig.Set(OUTPUT_CONFIG_KEY_HTML, true)
		stdoutConfig.Set(configuration.MAX_THREADS, 10)

		ctx := pkgMocks.NewMockInvocationContext(mockCtl)
		ctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		ctx.EXPECT().GetConfiguration().Return(stdoutConfig).AnyTimes()
		ctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.1301.0"))).AnyTimes()
		ctx.EXPECT().Context().Return(t.Context()).AnyTimes()

		results := loadTestResults(t, "../../../internal/presenters/testdata/ufm/secrets.testresult.json")
		workflowData := ufm.CreateWorkflowDataFromTestResults(workflow.NewWorkflowIdentifier("test"), results)
		input := []workflow.Data{workflowData}

		outputDestination := &stubOutputDestination{}
		writers := GetWritersFromConfiguration(stdoutConfig, outputDestination)

		remaining, err := HandleContentTypeUnifiedModel(input, ctx, writers)
		assert.NoError(t, err)
		assert.NotNil(t, remaining)

		stdout := outputDestination.buffer.String()
		assert.Contains(t, strings.ToLower(stdout), "<!doctype html>", "default writer should have received HTML output")
	})
}

func automationDetailsIDs(t *testing.T, sarifBytes []byte) []string {
	t.Helper()
	var doc struct {
		Runs []struct {
			AutomationDetails struct {
				ID string `json:"id"`
			} `json:"automationDetails"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(sarifBytes, &doc))
	ids := make([]string, 0, len(doc.Runs))
	for _, run := range doc.Runs {
		ids = append(ids, run.AutomationDetails.ID)
	}
	require.NotEmpty(t, ids)
	return ids
}

func Test_HandleContentTypeUnifiedModel_allOutputsOfOneRunShareAutomationDetailsId(t *testing.T) {
	for _, threads := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d threads", threads), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				runStart := time.Now()
				config := configuration.NewWithOpts()
				config.Set(configuration.MAX_THREADS, threads)

				logger := zerolog.Nop()
				mockCtl := gomock.NewController(t)
				ctx := pkgMocks.NewMockInvocationContext(mockCtl)
				ctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
				ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()
				// each renderer fetches the runtime info once before it renders; making
				// every later renderer start a fake second after the previous one
				// separates their clock reads whether they run serially or in parallel
				var renderersStarted atomic.Int64
				ctx.EXPECT().GetRuntimeInfo().DoAndReturn(func() runtimeinfo.RuntimeInfo {
					time.Sleep(time.Duration(renderersStarted.Add(1)-1) * time.Second)
					return runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.1301.0"))
				}).Times(2)
				ctx.EXPECT().Context().Return(t.Context()).AnyTimes()

				results := loadTestResults(t, "../../../internal/presenters/testdata/ufm/secrets.testresult.json")
				input := []workflow.Data{ufm.CreateWorkflowDataFromTestResults(workflow.NewWorkflowIdentifier("test"), results)}

				stdout := &bytes.Buffer{}
				sarifFile := &bytes.Buffer{}
				writers := &testWriterMap{
					writers: map[string][]*WriterEntry{
						SARIF_MIME_TYPE: {
							{writer: &nopCloser{writer: stdout}, mimeType: SARIF_MIME_TYPE, renderEmptyData: true, name: DEFAULT_WRITER},
							{writer: &nopCloser{writer: sarifFile}, mimeType: SARIF_MIME_TYPE, renderEmptyData: true, name: OUTPUT_CONFIG_KEY_SARIF_FILE},
						},
					},
				}

				_, err := HandleContentTypeUnifiedModel(input, ctx, writers)
				require.NoError(t, err)

				expectedID := "Snyk/Secrets/0/" + runStart.UTC().Format(time.RFC3339)
				assert.Equal(t, []string{expectedID}, automationDetailsIDs(t, stdout.Bytes()), "stdout")
				assert.Equal(t, []string{expectedID}, automationDetailsIDs(t, sarifFile.Bytes()), "sarif file")
			})
		})
	}
}
