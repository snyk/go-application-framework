package output_workflow

import (
	"bytes"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	pkgMocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

func getLocalFindingsSkeleton(t *testing.T, count uint32) []*local_models.LocalFinding {
	t.Helper()

	localFindings := make([]*local_models.LocalFinding, 0)
	localFindings = append(localFindings, &local_models.LocalFinding{
		Summary: struct {
			Artifacts int                             `json:"artifacts"`
			Counts    local_models.TypesFindingCounts `json:"counts"`
			Coverage  []local_models.TypesCoverage    `json:"coverage"`
			Path      string                          `json:"path"`
			Type      string                          `json:"type"`
		}{},
	})
	localFindings[0].Summary.Counts.Count = count
	return localFindings
}

func Test_getTotalNumberOfFindings(t *testing.T) {
	t.Run("nil findings", func(t *testing.T) {
		expectedCount := uint32(0)
		var localFindings []*local_models.LocalFinding

		// method under test
		actualCount := getTotalNumberOfFindings(localFindings)
		assert.Equal(t, expectedCount, actualCount)
	})

	t.Run("count multiple findings", func(t *testing.T) {
		expectedCount := uint32(8)
		localFindings := getLocalFindingsSkeleton(t, 2)
		localFindings = append(localFindings, getLocalFindingsSkeleton(t, 6)...)

		// method under test
		actualCount := getTotalNumberOfFindings(localFindings)
		assert.Equal(t, expectedCount, actualCount)
	})
}

func Test_useRendererWith(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.NewWithOpts()
	mockCtl := gomock.NewController(t)
	ctx := pkgMocks.NewMockInvocationContext(mockCtl)
	ctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()
	ctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()

	t.Run("render non empty input", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writer := &WriterEntry{
			writer:          &newLineCloser{writer: buffer},
			mimeType:        DEFAULT_MIME_TYPE,
			templates:       DefaultTemplateFiles,
			renderEmptyData: true,
		}
		findings := getLocalFindingsSkeleton(t, 2)
		useRendererWith("", writer, findings, ctx)
		assert.NotEmpty(t, buffer)
	})

	t.Run("render empty input", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writer := &WriterEntry{
			writer:          &newLineCloser{writer: buffer},
			mimeType:        DEFAULT_MIME_TYPE,
			templates:       DefaultTemplateFiles,
			renderEmptyData: true,
		}
		findings := getLocalFindingsSkeleton(t, 0)
		useRendererWith("", writer, findings, ctx)
		assert.NotEmpty(t, buffer)
	})

	t.Run("don't render empty input", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writer := &WriterEntry{
			writer:          &newLineCloser{writer: buffer},
			mimeType:        DEFAULT_MIME_TYPE,
			templates:       DefaultTemplateFiles,
			renderEmptyData: false,
		}
		findings := getLocalFindingsSkeleton(t, 0)
		useRendererWith("", writer, findings, ctx)
		assert.Empty(t, buffer)
	})
}
