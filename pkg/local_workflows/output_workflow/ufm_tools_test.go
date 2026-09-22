package output_workflow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	pkgMocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func loadTestResults(t *testing.T) []testapi.TestResult {
	t.Helper()
	testResultBytes, err := os.ReadFile("../../../internal/presenters/testdata/ufm/secrets.testresult.json")
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
		results := loadTestResults(t)
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

		results := loadTestResults(t)
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

		results := loadTestResults(t)
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

		results := loadTestResults(t)
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

		results := loadTestResults(t)
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

	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprintf("toon stdout and file/full=%t", full), func(t *testing.T) {
			mockCtl := gomock.NewController(t)
			defer mockCtl.Finish()

			stdoutConfig := configuration.NewWithOpts()
			mode := "compact"
			if full {
				mode = "full"
			}
			stdoutConfig.Set(OUTPUT_CONFIG_KEY_TOON, mode)
			outputFile := filepath.Join(t.TempDir(), "results.toon")
			stdoutConfig.Set(OUTPUT_CONFIG_KEY_TOON_FILE, outputFile)
			stdoutConfig.Set(configuration.MAX_THREADS, 10)

			ctx := pkgMocks.NewMockInvocationContext(mockCtl)
			ctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
			ctx.EXPECT().GetConfiguration().Return(stdoutConfig).AnyTimes()
			ctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
			invocationContext := context.WithValue(t.Context(), networking.InteractionIdKey, "interaction-test")
			ctx.EXPECT().Context().Return(invocationContext).AnyTimes()

			results, err := ufm.NewSerializableTestResultFromBytes([]byte(`[{"findings":[{"attributes":{
	            "finding_type":"secret","title":"example-rule","description":"excluded","rating":{"severity":"low"},
	            "locations":[{"type":"source","file_path":"example.txt","from_line":5,"to_line":8}]
	        }}, {"id":"00000000-0000-4000-8000-000000000002","attributes":{
	            "finding_type":"sca","title":"Example","rating":{"severity":"low"},"problems":[{"source":"snyk_vuln","id":"example","cvss_base_score":0}],
	            "locations":[{"type":"package","package":{"name":"example","version":"1"}}]
	        }}, {"id":"00000000-0000-4000-8000-000000000004","attributes":{
	            "finding_type":"sca","title":"Later occurrence","rating":{"severity":"low"},"problems":[{"source":"snyk_vuln","id":"example"}],
	            "locations":[{"type":"package","package":{"name":"example","version":"1.5"}}]
	        },"relationships":{"fix":{"data":{"attributes":{"action":{"format":"upgrade_package_advice",
	            "upgrade_paths":[{"dependency_path":[{"name":"root","version":"1"},{"name":"example","version":"2"}]}]}
	        }}}}}, {"id":"00000000-0000-4000-8000-000000000003","attributes":{
	            "finding_type":"future","title":"Future finding","rating":{"severity":"medium"}
	        }}]}]`))
			assert.NoError(t, err)
			workflowData := ufm.CreateWorkflowDataFromTestResults(workflow.NewWorkflowIdentifier("test"), results)
			input := []workflow.Data{workflowData}

			outputDestination := &stubOutputDestination{}
			writers := GetWritersFromConfiguration(stdoutConfig, outputDestination)

			remaining, err := HandleContentTypeUnifiedModel(input, ctx, writers)
			assert.NoError(t, err)
			assert.NotNil(t, remaining)
			expected := "sca[1]{fixable,id,pkg,severity}:\n  yes,example,\"example@1,1.5\",\"\""
			if full {
				expected = "sca[1]{cvss,fixable,id,pkg,severity,title,upgrade}:\n  \"0.0\",yes,example,\"example@1,1.5\",\"\",Example,example@2"
			}
			expected += "\nsecrets[1]{file,line,rule,severity}:\n  example.txt,5,example-rule,low"
			header := "interaction_id: interaction-test\norg: unknown\nproject: unknown\n"
			if !full {
				header = "hint: add --toon=full for all fields\n" + header
			}
			expected = "findings[1]{finding_type,id,severity,title}:\n  future,00000000-0000-4000-8000-000000000003,medium,Future finding\n" + header + expected
			assert.Equal(t, expected+"\n", outputDestination.buffer.String())
			content, err := os.ReadFile(outputFile)
			assert.NoError(t, err)
			assert.Equal(t, expected, string(content))

			if !full {
				unfinishedResults, parseErr := ufm.NewSerializableTestResultFromBytes([]byte(
					`[{"findingsComplete":true,"executionState":"started","testConfiguration":{"scan_config":{"secrets":{}}}}]`))
				assert.NoError(t, parseErr)
				unfinishedData := ufm.CreateWorkflowDataFromTestResults(workflow.NewWorkflowIdentifier("test"), unfinishedResults)
				unfinishedDestination := &stubOutputDestination{}
				unfinishedWriters := GetWritersFromConfiguration(stdoutConfig, unfinishedDestination)
				_, renderErr := HandleContentTypeUnifiedModel([]workflow.Data{unfinishedData}, ctx, unfinishedWriters)
				assert.ErrorContains(t, renderErr, "scan is started")
				assert.Empty(t, unfinishedDestination.buffer.String())
				content, readErr := os.ReadFile(outputFile)
				assert.NoError(t, readErr)
				assert.Equal(t, expected, string(content), "existing output must remain untouched")
			}
		})
	}
}
