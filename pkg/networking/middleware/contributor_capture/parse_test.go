package contributor_capture_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cc "github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
)

// extractorTest is a body and the entity ID an extractor should find in it.
// A body that cannot be parsed yields no ID.
type extractorTest struct {
	name     string
	body     string
	expected string
}

func runExtractorTests(t *testing.T, extract func(io.Reader) (string, error), tests []extractorTest) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := extract(strings.NewReader(tt.body))
			assert.Equal(t, tt.expected, got)
			if tt.expected != "" {
				require.NoError(t, err)
			}
		})
	}
}

func TestExtractMonitorProjectID(t *testing.T) {
	t.Parallel()
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	runExtractorTests(t, cc.ExtractMonitorProjectID, []extractorTest{
		{
			name:     "valid monitor response",
			body:     `{"id":"test","uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccc"}`,
			expected: projectID,
		},
		{
			// The field capture needs is serialized after the license policy,
			// which is why the body is streamed rather than read to a cap.
			name:     "uri behind a large licenses policy",
			body:     `{"ok":true,"licensesPolicy":{"severities":` + bigLicensePolicy(2<<20) + `},"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccc"}`,
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
		{
			name:     "uri is not a string",
			body:     `{"uri":{"nested":"value"}}`,
			expected: "",
		},
	})
}

func TestExtractCreateTestReport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		expected  bool
		wantKnown bool
	}{
		{
			name:      "new style report true",
			body:      `{"data":{"attributes":{"configuration":{"output":{"report":true}}}}}`,
			expected:  true,
			wantKnown: true,
		},
		{
			name:      "new style report false",
			body:      `{"data":{"attributes":{"configuration":{"output":{"report":false}}}}}`,
			expected:  false,
			wantKnown: true,
		},
		{
			name:      "legacy publish_report true",
			body:      `{"data":{"attributes":{"config":{"publish_report":true}}}}`,
			expected:  true,
			wantKnown: true,
		},
		{
			name:      "legacy monitor only (rejected)",
			body:      `{"data":{"attributes":{"config":{"monitor":true,"scan_config":{"sca":{}}}}}}`,
			expected:  false,
			wantKnown: true,
		},
		{
			name:      "monitor wins over a configured report",
			body:      `{"data":{"attributes":{"config":{"monitor":true},"configuration":{"output":{"report":true}}}}}`,
			expected:  false,
			wantKnown: true,
		},
		{
			name:      "neither shape present",
			body:      `{"data":{"attributes":{"scan_type":"sca"}}}`,
			expected:  false,
			wantKnown: true,
		},
		{
			name:      "invalid json",
			body:      `{invalid}`,
			expected:  false,
			wantKnown: false,
		},
		{
			name:      "truncated json",
			body:      `{"data":{"attributes":{"configuration":{"output":{"rep`,
			expected:  false,
			wantKnown: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report, known, err := cc.ExtractCreateTestReport(strings.NewReader(tt.body))
			assert.Equal(t, tt.expected, report)
			assert.Equal(t, tt.wantKnown, known, "an unreadable body must not read as a declined report")
			if tt.wantKnown {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestExtractCreateTestID(t *testing.T) {
	t.Parallel()

	runExtractorTests(t, cc.ExtractCreateTestID, []extractorTest{
		{
			name:     "valid id",
			body:     `{"data":{"id":"22222222-2222-4222-8222-222222222222"}}`,
			expected: "22222222-2222-4222-8222-222222222222",
		},
		{
			name:     "id behind a large sibling",
			body:     `{"meta":{"noise":"` + strings.Repeat("n", 1<<20) + `"},"data":{"id":"22222222-2222-4222-8222-222222222222"}}`,
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
	})
}

func TestExtractComponentsProjectID(t *testing.T) {
	t.Parallel()
	const projectID = "44444444-4444-4444-8444-444444444444"

	runExtractorTests(t, cc.ExtractComponentsProjectID, []extractorTest{
		{
			name:     "sast successful component",
			body:     `{"data":[{"attributes":{"type":"sast","success":true,"webui":{"project_id":"` + projectID + `"}}}]}`,
			expected: projectID,
		},
		{
			name:     "unsuccessful component skipped",
			body:     `{"data":[{"attributes":{"type":"sast","success":false,"webui":{"project_id":"` + projectID + `"}}}]}`,
			expected: "",
		},
		{
			name:     "first successful sast component after others",
			body:     `{"data":[{"attributes":{"type":"sca","success":true,"webui":{"project_id":"11111111-1111-4111-8111-111111111111"}}},{"attributes":{"type":"sast","success":true,"webui":{"project_id":"` + projectID + `"}}}]}`,
			expected: projectID,
		},
		{
			name:     "empty data",
			body:     `{"data":[]}`,
			expected: "",
		},
		{
			name:     "invalid json",
			body:     `{invalid}`,
			expected: "",
		},
	})
}

func TestExtractIaCShareProjectID(t *testing.T) {
	t.Parallel()

	runExtractorTests(t, cc.ExtractIaCShareProjectID, []extractorTest{
		{
			// Only one entity is reported per invocation, so the first project
			// in the response is the one taken.
			name:     "first project id of several",
			body:     `{"./main.tf":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","./other.tf":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee","ok":true}`,
			expected: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		},
		{
			name:     "metadata keys skipped",
			body:     `{"ok":true,"meta":{"isPrivate":false},"./main.tf":"dddddddd-dddd-4ddd-8ddd-dddddddddddd"}`,
			expected: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		},
		{
			name:     "non uuid values skipped",
			body:     `{"./a.tf":"not-a-uuid","./b.tf":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}`,
			expected: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		},
		{
			name:     "no project ids",
			body:     `{"ok":true}`,
			expected: "",
		},
		{
			name:     "invalid json",
			body:     `{invalid}`,
			expected: "",
		},
	})
}

func TestExtractAIBomUploadRevisionID(t *testing.T) {
	t.Parallel()
	const revisionID = "19d7450b-886f-4029-9b60-1b309b85b800"

	runExtractorTests(t, cc.ExtractAIBomUploadRevisionID, []extractorTest{
		{
			name:     "valid revision id",
			body:     `{"data":{"attributes":{"upload_revision_id":"` + revisionID + `"}}}`,
			expected: revisionID,
		},
		{
			// The rest of the request is the uploaded document, which is why
			// the request body is streamed rather than read to a cap.
			name:     "revision id behind a large document",
			body:     `{"data":{"attributes":{"document":"` + strings.Repeat("d", 2<<20) + `","upload_revision_id":"` + revisionID + `"}}}`,
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
	})
}

func TestExtractDeeproxyReportProjectID(t *testing.T) {
	t.Parallel()
	const projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"

	tests := []extractorTest{
		{
			name:     "complete body",
			body:     `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `","snapshotId":"abc"},"analysisResults":{}}`,
			expected: projectID,
		},
		{
			name:     "truncated in a later sibling",
			body:     `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `"},"analysisResults":{"files":[{"data":"` + strings.Repeat("x", 100),
			expected: projectID,
		},
		{
			name:     "truncated at top level after uploadResult",
			body:     `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `"},"analysisRes`,
			expected: projectID,
		},
		{
			name:     "projectId not first key in uploadResult",
			body:     `{"status":"COMPLETE","uploadResult":{"bundleHash":"abc","projectId":"` + projectID + `"}}`,
			expected: projectID,
		},
		{
			name:     "nested uploadResult ignored",
			body:     `{"status":"COMPLETE","analysisResults":{"uploadResult":{"projectId":"` + projectID + `"}}}`,
			expected: "",
		},
		{
			// The scan returns at the field it wants, so what follows being
			// truncated no longer loses an ID that was already read.
			name:     "truncated after projectId inside uploadResult",
			body:     `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `","snapshotId"`,
			expected: projectID,
		},
		{
			name:     "truncated mid project id",
			body:     `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID[:20],
			expected: "",
		},
		{
			name:     "no uploadResult",
			body:     `{"status":"WAITING","progress":0.5}`,
			expected: "",
		},
		{
			name:     "uploadResult without projectId",
			body:     `{"status":"COMPLETE","uploadResult":{"bundleHash":"abc"}}`,
			expected: "",
		},
		{
			name:     "uploadResult is not an object",
			body:     `{"status":"COMPLETE","uploadResult":"nope"}`,
			expected: "",
		},
		{
			name:     "projectId is not a uuid",
			body:     `{"status":"COMPLETE","uploadResult":{"projectId":"not-a-uuid"}}`,
			expected: "",
		},
		{
			name:     "invalid json",
			body:     `{invalid}`,
			expected: "",
		},
		{
			name:     "empty body",
			body:     ``,
			expected: "",
		},
		{
			name:     "top level array",
			body:     `[1,2,3]`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := cc.ExtractDeeproxyReportProjectID(gzipped(t, tt.body))
			assert.Equal(t, tt.expected, got)
			if tt.expected != "" {
				require.NoError(t, err)
			}
		})
	}
}

func TestExtractDeeproxyReportProjectID_rejectsBodyThatIsNotGzipped(t *testing.T) {
	t.Parallel()

	_, err := cc.ExtractDeeproxyReportProjectID(strings.NewReader(`{"uploadResult":{"projectId":"25bcb5ba-5b16-4f56-8620-4e3a508f67ed"}}`))
	require.Error(t, err)
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

// gzipped returns body as the gzip stream a deeproxy report arrives as.
func gzipped(t *testing.T, body string) io.Reader {
	t.Helper()

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write([]byte(body))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	return &buf
}

// bigLicensePolicy builds a license policy of roughly size bytes, the field
// that pushes a monitor response past any fixed read limit.
func bigLicensePolicy(size int) string {
	var buf bytes.Buffer
	buf.WriteString("{")
	for i := 0; buf.Len() < size; i++ {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(`"LICENSE-`)
		buf.WriteString(strings.Repeat("A", 8))
		buf.WriteString("-")
		buf.WriteString(strings.Repeat("0", 4))
		buf.WriteString(`-`)
		buf.WriteString(string(rune('a' + i%26)))
		buf.WriteString(`":{"severity":"high","instructions":"`)
		buf.WriteString(strings.Repeat("i", 512))
		buf.WriteString(`"}`)
	}
	buf.WriteString("}")

	return buf.String()
}
