package contributor_capture_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	cc "github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
)

func TestParseMonitorProjectIDs_fromURI(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"uri": "https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	}`)

	id := cc.ParseMonitorProjectID(body)
	assert.Equal(t, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", id)
}

func TestParseIaCShareProjectIDs(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"./main.tf": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		"./other.tf": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		"ok": true
	}`)

	ids := cc.ParseIaCShareProjectIDs(body)
	assert.Len(t, ids, 2)
	assert.ElementsMatch(t, []string{
		"dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
	}, ids)
}

func TestParseCreateTestPublishReport_requiresPublishReportFlag(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"data": {
			"attributes": {
				"configuration": {
					"output": {
						"report": false
					}
				}
			}
		}
	}`)
	assert.False(t, cc.ParseCreateTestPublishReport(body))

	body = []byte(`{
		"data": {
			"attributes": {
				"configuration": {
					"output": {
						"report": true
					}
				}
			}
		}
	}`)
	assert.True(t, cc.ParseCreateTestPublishReport(body))
}

func TestParseCreateTestPublishReport_legacyPublishReportFlag(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"data": {
			"attributes": {
				"config": {
					"publish_report": true
				}
			}
		}
	}`)
	assert.True(t, cc.ParseCreateTestPublishReport(body))
}

func TestParseCreateTestPublishReport_rejectsMonitorOnly(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"data": {
			"attributes": {
				"config": {
					"monitor": true,
					"scan_config": {"sca": {}}
				}
			}
		}
	}`)
	assert.False(t, cc.ParseCreateTestPublishReport(body))
}

func TestParseCreateTestPublishReport_rejectsPublishReportFalse(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"data": {
			"attributes": {
				"config": {
					"publish_report": false
				}
			}
		}
	}`)
	assert.False(t, cc.ParseCreateTestPublishReport(body))
}

func TestParseCreateTestPublishReport_handlesInvalidJSON(t *testing.T) {
	t.Parallel()

	body := []byte(`not valid json`)
	assert.False(t, cc.ParseCreateTestPublishReport(body))
}

func TestParseCreateTestPublishReport_handlesMissingPublishReport(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"data": {
			"attributes": {
				"config": {}
			}
		}
	}`)
	assert.False(t, cc.ParseCreateTestPublishReport(body))
}

func TestParseCreateTestID(t *testing.T) {
	t.Parallel()

	body := []byte(`{"data":{"id":"22222222-2222-4222-8222-222222222222"}}`)
	assert.Equal(t, "22222222-2222-4222-8222-222222222222", cc.ParseCreateTestID(body))
}

func TestParseComponentsProjectIDs_sastWebuiProject(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"data": [{
			"attributes": {
				"type": "sast",
				"success": true,
				"webui": {"project_id": "44444444-4444-4444-8444-444444444444"}
			}
		}]
	}`)

	id := cc.ParseComponentsProjectID(body)
	assert.Equal(t, "44444444-4444-4444-8444-444444444444", id)
}

func TestParseComponentsProjectIDs_unsuccessfulSkipped(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"data": [{
			"attributes": {
				"type": "sast",
				"success": false,
				"webui": {"project_id": "44444444-4444-4444-8444-444444444444"}
			}
		}]
	}`)

	assert.Empty(t, cc.ParseComponentsProjectID(body))
}

func TestParseAIBomUploadRevisionIDs(t *testing.T) {
	t.Parallel()

	const revisionID = "19d7450b-886f-4029-9b60-1b309b85b800"

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "upload request",
			body: `{"data":{"attributes":{"repo_name":"acme/app","upload_revision_id":"` + revisionID + `"},"type":"ai_bom_file_upload"}}`,
			want: revisionID,
		},
		{
			name: "missing revision id",
			body: `{"data":{"attributes":{"repo_name":"acme/app"},"type":"ai_bom_file_upload"}}`,
		},
		{
			name: "revision id is not a uuid",
			body: `{"data":{"attributes":{"upload_revision_id":"not-a-uuid"}}}`,
		},
		{
			name: "malformed json",
			body: `{"data":`,
		},
		{
			name: "empty body",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, cc.ParseAIBomUploadRevisionID([]byte(tc.body)))
		})
	}
}

func TestParseDeeproxyReportProjectID_completeUploadResult(t *testing.T) {
	t.Parallel()

	const projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	body := []byte(`{
		"status": "COMPLETE",
		"uploadResult": {
			"projectId": "` + projectID + `",
			"snapshotId": "28831237-953d-4baa-ba5f-2a6b01ba5b94"
		}
	}`)

	assert.Equal(t, projectID, cc.ParseDeeproxyReportProjectID(body))
}

func TestParseDeeproxyReportProjectID_ignoresIncompleteStatus(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"status": "IN_PROGRESS",
		"uploadResult": {"projectId": "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"}
	}`)

	assert.Empty(t, cc.ParseDeeproxyReportProjectID(body))
}

func TestParseDeeproxyReportProjectID_projectIDSnakeCase(t *testing.T) {
	t.Parallel()

	const projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	body := []byte(`{
		"status": "COMPLETE",
		"uploadResult": {
			"project_id": "` + projectID + `"
		}
	}`)

	assert.Equal(t, projectID, cc.ParseDeeproxyReportProjectID(body))
}

func TestParseDeeproxyReportProjectID_truncatedBodyPrefix(t *testing.T) {
	t.Parallel()

	const projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	body := []byte(`{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `"` + `,"analysisResult":{"type":"sarif","data":"` + strings.Repeat("x", 100) + `"`)

	assert.Equal(t, projectID, cc.ParseDeeproxyReportProjectID(body))
}
