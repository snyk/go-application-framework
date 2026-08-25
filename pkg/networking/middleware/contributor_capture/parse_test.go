package contributor_capture_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cc "github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
)

func TestParseMonitorProjectID(t *testing.T) {
	t.Parallel()
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "valid monitor response",
			body:     `{"id":"test","uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccc"}`,
			expected: projectID,
		},
		{
			name:     "invalid json",
			body:     `{invalid}`,
			expected: "",
		},
		{
			name:     "missing uri field",
			body:     `{"id":"test"}`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, cc.ParseMonitorProjectID([]byte(tt.body)))
		})
	}
}

func TestParseCreateTestPublishReport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "new style report true",
			body:     `{"data":{"attributes":{"configuration":{"output":{"report":true}}}}}`,
			expected: true,
		},
		{
			name:     "new style report false",
			body:     `{"data":{"attributes":{"configuration":{"output":{"report":false}}}}}`,
			expected: false,
		},
		{
			name:     "legacy publish_report true",
			body:     `{"data":{"attributes":{"config":{"publish_report":true}}}}`,
			expected: true,
		},
		{
			name:     "legacy monitor only (rejected)",
			body:     `{"data":{"attributes":{"config":{"monitor":true,"scan_config":{"sca":{}}}}}}`,
			expected: false,
		},
		{
			name:     "invalid json",
			body:     `{invalid}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, cc.ParseCreateTestPublishReport([]byte(tt.body)))
		})
	}
}

func TestParseCreateTestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "valid id",
			body:     `{"data":{"id":"22222222-2222-4222-8222-222222222222"}}`,
			expected: "22222222-2222-4222-8222-222222222222",
		},
		{
			name:     "invalid json",
			body:     `{invalid}`,
			expected: "",
		},
		{
			name:     "invalid uuid",
			body:     `{"data":{"id":"not-a-uuid"}}`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, cc.ParseCreateTestID([]byte(tt.body)))
		})
	}
}

func TestParseComponentsProjectID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "sast successful component",
			body:     `{"data":[{"attributes":{"type":"sast","success":true,"webui":{"project_id":"44444444-4444-4444-8444-444444444444"}}}]}`,
			expected: "44444444-4444-4444-8444-444444444444",
		},
		{
			name:     "unsuccessful component skipped",
			body:     `{"data":[{"attributes":{"type":"sast","success":false,"webui":{"project_id":"44444444-4444-4444-8444-444444444444"}}}]}`,
			expected: "",
		},
		{
			name:     "invalid json",
			body:     `{invalid}`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, cc.ParseComponentsProjectID([]byte(tt.body)))
		})
	}
}

func TestParseIaCShareProjectIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		expected []string
	}{
		{
			name:     "valid project ids",
			body:     `{"./main.tf":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","./other.tf":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee","ok":true}`,
			expected: []string{"dddddddd-dddd-4ddd-8ddd-dddddddddddd", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"},
		},
		{
			name:     "invalid json",
			body:     `{invalid}`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := cc.ParseIaCShareProjectIDs([]byte(tt.body))
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				require.Len(t, result, len(tt.expected))
				assert.ElementsMatch(t, tt.expected, result)
			}
		})
	}
}

func TestParseAIBomUploadRevisionID(t *testing.T) {
	t.Parallel()
	const revisionID = "19d7450b-886f-4029-9b60-1b309b85b800"

	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "valid revision id",
			body:     `{"data":{"attributes":{"upload_revision_id":"` + revisionID + `"}}}`,
			expected: revisionID,
		},
		{
			name:     "missing revision id",
			body:     `{"data":{"attributes":{}}}`,
			expected: "",
		},
		{
			name:     "invalid json",
			body:     `{invalid}`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, cc.ParseAIBomUploadRevisionID([]byte(tt.body)))
		})
	}
}

func TestParseDeeproxyReportProjectID(t *testing.T) {
	t.Parallel()
	const projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"

	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "complete with projectId",
			body:     `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `"}}`,
			expected: projectID,
		},
		{
			name:     "complete with project_id",
			body:     `{"status":"COMPLETE","uploadResult":{"project_id":"` + projectID + `"}}`,
			expected: projectID,
		},
		{
			name:     "incomplete status",
			body:     `{"status":"IN_PROGRESS","uploadResult":{"projectId":"` + projectID + `"}}`,
			expected: "",
		},
		{
			name:     "truncated body (fallback parsing)",
			body:     `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `","analysisResult":{"type":"sarif","data":"` + strings.Repeat("x", 100),
			expected: projectID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, cc.ParseDeeproxyReportProjectID([]byte(tt.body)))
		})
	}
}

func TestProjectIDFromMonitorURI(t *testing.T) {
	t.Parallel()
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "standard uri with history",
			uri:      `https://app.snyk.io/org/acme/project/` + projectID + `/history/aaaa`,
			expected: projectID,
		},
		{
			name:     "uri ending with project id",
			uri:      `https://app.snyk.io/project/` + projectID,
			expected: projectID,
		},
		{
			name:     "missing project path",
			uri:      `https://app.snyk.io/org/acme/history/aaaa`,
			expected: "",
		},
		{
			name:     "invalid uuid",
			uri:      `https://app.snyk.io/project/not-a-uuid/history`,
			expected: "",
		},
		{
			name:     "empty uri",
			uri:      "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, cc.ProjectIDFromMonitorURI(tt.uri))
		})
	}
}
