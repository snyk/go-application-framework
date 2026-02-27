package output_workflow

import (
	"bytes"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	pkgMocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_getOtherResultsFromWorkflowData(t *testing.T) {
	workflowID := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "test")

	t.Run("empty input returns empty slices", func(t *testing.T) {
		otherData, remainingData := getOtherResultsFromWorkflowData([]workflow.Data{})
		assert.Empty(t, otherData)
		assert.Empty(t, remainingData)
	})

	t.Run("TEST_SUMMARY is filtered to remaining", func(t *testing.T) {
		summaryData := workflow.NewData(workflowID, content_type.TEST_SUMMARY, []byte("{}"))
		otherData, remainingData := getOtherResultsFromWorkflowData([]workflow.Data{summaryData})
		assert.Empty(t, otherData)
		assert.Len(t, remainingData, 1)
		assert.Equal(t, summaryData, remainingData[0])
	})

	t.Run("versioned TEST_SUMMARY is filtered to remaining via prefix match", func(t *testing.T) {
		versionedSummary := workflow.NewData(workflowID, content_type.TEST_SUMMARY+"; version=2024-04-10", []byte("{}"))
		otherData, remainingData := getOtherResultsFromWorkflowData([]workflow.Data{versionedSummary})
		assert.Empty(t, otherData)
		assert.Len(t, remainingData, 1)
	})

	t.Run("non-ignored mimetypes go to otherData", func(t *testing.T) {
		jsonData := workflow.NewData(workflowID, "application/json", []byte("{}"))
		xmlData := workflow.NewData(workflowID, "application/xml", []byte("<xml/>"))
		otherData, remainingData := getOtherResultsFromWorkflowData([]workflow.Data{jsonData, xmlData})
		assert.Len(t, otherData, 2)
		assert.Empty(t, remainingData)
	})

	t.Run("mixed input is correctly separated", func(t *testing.T) {
		summaryData := workflow.NewData(workflowID, content_type.TEST_SUMMARY, []byte("{}"))
		jsonData := workflow.NewData(workflowID, "application/json", []byte("{}"))
		otherData, remainingData := getOtherResultsFromWorkflowData([]workflow.Data{summaryData, jsonData})
		assert.Len(t, otherData, 1)
		assert.Equal(t, jsonData, otherData[0])
		assert.Len(t, remainingData, 1)
		assert.Equal(t, summaryData, remainingData[0])
	})
}

func Test_useWriterWithOther(t *testing.T) {
	logger := zerolog.Nop()
	workflowID := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "test")

	t.Run("writes byte payload to writer", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writer := &WriterEntry{
			writer:   &nopCloser{writer: buffer},
			mimeType: JSON_MIME_TYPE,
			name:     "test-writer",
		}
		data := workflow.NewData(workflowID, "application/json", []byte(`{"key":"value"}`))

		written, err := useWriterWithOther(&logger, []workflow.Data{data}, []*WriterEntry{writer})
		assert.NoError(t, err)
		assert.True(t, written)
		assert.Equal(t, `{"key":"value"}`, buffer.String())
	})

	t.Run("writes string payload to writer", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writer := &WriterEntry{
			writer:   &nopCloser{writer: buffer},
			mimeType: DEFAULT_MIME_TYPE,
			name:     "test-writer",
		}
		data := workflow.NewData(workflowID, "text/plain", "hello world")

		written, err := useWriterWithOther(&logger, []workflow.Data{data}, []*WriterEntry{writer})
		assert.NoError(t, err)
		assert.True(t, written)
		assert.Equal(t, "hello world", buffer.String())
	})

	t.Run("returns error for unsupported payload type", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writer := &WriterEntry{
			writer:   &nopCloser{writer: buffer},
			mimeType: DEFAULT_MIME_TYPE,
			name:     "test-writer",
		}
		data := workflow.NewData(workflowID, "hammer/head", 12345)

		written, err := useWriterWithOther(&logger, []workflow.Data{data}, []*WriterEntry{writer})
		assert.Error(t, err)
		assert.False(t, written)
		assert.Contains(t, err.Error(), "unsupported output type: hammer/head")
	})

	t.Run("no writer slice returns dataWasWritten false", func(t *testing.T) {
		data := workflow.NewData(workflowID, "application/json", []byte(`{}`))

		written, err := useWriterWithOther(&logger, []workflow.Data{data}, []*WriterEntry{})
		assert.NoError(t, err)
		assert.False(t, written)
	})
}

func Test_HandleContentTypeOther(t *testing.T) {
	workflowID := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "test")

	newMockContext := func(t *testing.T) workflow.InvocationContext {
		t.Helper()
		logger := zerolog.Nop()
		config := configuration.NewWithOpts()
		ctrl := gomock.NewController(t)
		ctx := pkgMocks.NewMockInvocationContext(ctrl)
		ctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()
		return ctx
	}

	t.Run("empty input returns no error", func(t *testing.T) {
		ctx := newMockContext(t)
		writers := &testWriterMap{writers: map[string][]*WriterEntry{}}

		remaining, err := HandleContentTypeOther([]workflow.Data{}, ctx, writers)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
	})

	t.Run("data is routed to the appropriate writer", func(t *testing.T) {
		ctx := newMockContext(t)
		buffer := &bytes.Buffer{}
		writers := &testWriterMap{
			writers: map[string][]*WriterEntry{
				JSON_MIME_TYPE: {{
					writer:   &nopCloser{writer: buffer},
					mimeType: JSON_MIME_TYPE,
					name:     "json-writer",
				}},
			},
		}

		data := workflow.NewData(workflowID, "application/json", []byte(`{"a":1}`))
		remaining, err := HandleContentTypeOther([]workflow.Data{data}, ctx, writers)
		assert.NoError(t, err)
		assert.Equal(t, `{"a":1}`, buffer.String())
		assert.Empty(t, remaining)
	})

	t.Run("data is routed to the appropriate writer via fuzzy match", func(t *testing.T) {
		ctx := newMockContext(t)
		buffer := &bytes.Buffer{}
		writers := &testWriterMap{
			writers: map[string][]*WriterEntry{
				JSON_MIME_TYPE: {{
					writer:   &nopCloser{writer: buffer},
					mimeType: JSON_MIME_TYPE,
					name:     "json-writer",
				}},
			},
		}

		data := workflow.NewData(workflowID, "application/vnd.cyclonedx+json", []byte(`{"bom":true}`))
		remaining, err := HandleContentTypeOther([]workflow.Data{data}, ctx, writers)
		assert.NoError(t, err)
		assert.Equal(t, `{"bom":true}`, buffer.String())
		assert.Empty(t, remaining)
	})

	t.Run("unmatched data falls through to default writer", func(t *testing.T) {
		ctx := newMockContext(t)
		buffer := &bytes.Buffer{}
		writers := &testWriterMap{
			writers: map[string][]*WriterEntry{
				DEFAULT_MIME_TYPE: {{
					writer:   &nopCloser{writer: buffer},
					mimeType: DEFAULT_MIME_TYPE,
					name:     "default-writer",
				}},
			},
		}

		data := workflow.NewData(workflowID, "application/xml", []byte(`<xml/>`))
		_, err := HandleContentTypeOther([]workflow.Data{data}, ctx, writers)
		assert.NoError(t, err)
		assert.Equal(t, `<xml/>`, buffer.String())
	})

	t.Run("multiple data items with same mimetype are all written to the same writer", func(t *testing.T) {
		ctx := newMockContext(t)
		buffer := &bytes.Buffer{}
		writers := &testWriterMap{
			writers: map[string][]*WriterEntry{
				JSON_MIME_TYPE: {{
					writer:   &nopCloser{writer: buffer},
					mimeType: JSON_MIME_TYPE,
					name:     "json-writer",
				}},
			},
		}

		data1 := workflow.NewData(workflowID, "application/json", []byte(`{"a":1}`))
		data2 := workflow.NewData(workflowID, "application/json", []byte(`{"b":2}`))
		remaining, err := HandleContentTypeOther([]workflow.Data{data1, data2}, ctx, writers)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.Equal(t, `{"a":1}{"b":2}`, buffer.String())
	})

	t.Run("data with no matching writer is returned as remaining", func(t *testing.T) {
		ctx := newMockContext(t)
		writers := &testWriterMap{writers: map[string][]*WriterEntry{}}

		data := workflow.NewData(workflowID, "application/xml", []byte(`<xml/>`))
		remaining, err := HandleContentTypeOther([]workflow.Data{data}, ctx, writers)
		assert.NoError(t, err)
		assert.Contains(t, remaining, data)
	})
}
