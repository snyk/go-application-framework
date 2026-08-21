package capture_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
)

func TestMatchRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		path       string
		endpoint   capture.EndpointKind
		capability capture.Capability
		matched    bool
	}{
		{
			name:       "oss monitor",
			method:     "PUT",
			path:       "/v1/monitor/npm",
			endpoint:   capture.EndpointRegistryMonitor,
			capability: capture.CapabilityOSS,
			matched:    true,
		},
		{
			name:       "monitor dependencies",
			method:     "PUT",
			path:       "/v1/monitor-dependencies",
			endpoint:   capture.EndpointRegistryMonitor,
			capability: capture.CapabilityOSS,
			matched:    true,
		},
		{
			name:       "iac share",
			method:     "POST",
			path:       "/v1/iac-cli-share-results",
			endpoint:   capture.EndpointRegistryIaCShare,
			capability: capture.CapabilityIaC,
			matched:    true,
		},
		{
			name:     "create test",
			method:   "POST",
			path:     "/orgs/11111111-1111-4111-8111-111111111111/tests",
			endpoint: capture.EndpointTestCreate,
			matched:  true,
		},
		{
			name:     "create test hidden code api",
			method:   "POST",
			path:     "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests",
			endpoint: capture.EndpointTestCreate,
			matched:  true,
		},
		{
			name:     "get test job",
			method:   "GET",
			path:     "/orgs/11111111-1111-4111-8111-111111111111/test_jobs/22222222-2222-4222-8222-222222222222",
			endpoint: capture.EndpointTestJobGet,
			matched:  true,
		},
		{
			name:     "get test job hidden code api",
			method:   "GET",
			path:     "/hidden/orgs/11111111-1111-4111-8111-111111111111/test_jobs/22222222-2222-4222-8222-222222222222",
			endpoint: capture.EndpointTestJobGet,
			matched:  true,
		},
		{
			name:     "get test",
			method:   "GET",
			path:     "/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222",
			endpoint: capture.EndpointTestGet,
			matched:  true,
		},
		{
			name:     "get test hidden code api",
			method:   "GET",
			path:     "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222",
			endpoint: capture.EndpointTestGet,
			matched:  true,
		},
		{
			name:     "get components",
			method:   "GET",
			path:     "/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222/components",
			endpoint: capture.EndpointTestComponents,
			matched:  true,
		},
		{
			name:     "get components hidden code api",
			method:   "GET",
			path:     "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222/components",
			endpoint: capture.EndpointTestComponents,
			matched:  true,
		},
		{
			name:       "deeproxy legacy code report",
			method:     "GET",
			path:       "/report/55555555-5555-4555-8555-555555555555",
			endpoint:   capture.EndpointDeeproxyReport,
			capability: capture.CapabilityCode,
			matched:    true,
		},
		{
			name:       "deeproxy legacy code report trailing slash",
			method:     "GET",
			path:       "/report/55555555-5555-4555-8555-555555555555/",
			endpoint:   capture.EndpointDeeproxyReport,
			capability: capture.CapabilityCode,
			matched:    true,
		},
		{
			name:       "deeproxy legacy code report with query",
			method:     "GET",
			path:       "/report/55555555-5555-4555-8555-555555555555?version=2024-10-15",
			endpoint:   capture.EndpointDeeproxyReport,
			capability: capture.CapabilityCode,
			matched:    true,
		},
		{
			name:       "aibom upload rest path",
			method:     "POST",
			path:       "/rest/orgs/11111111-1111-4111-8111-111111111111/ai_boms/upload",
			endpoint:   capture.EndpointAIBOMUpload,
			capability: capture.CapabilityAIBOM,
			matched:    true,
		},
		{
			name:       "aibom upload without rest prefix",
			method:     "POST",
			path:       "/orgs/11111111-1111-4111-8111-111111111111/ai_boms/upload",
			endpoint:   capture.EndpointAIBOMUpload,
			capability: capture.CapabilityAIBOM,
			matched:    true,
		},
		{
			name:    "analytics ignored",
			method:  "POST",
			path:    "/v1/analytics/cli",
			matched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			endpoint, capability, matched := capture.MatchRequest(tt.method, tt.path)
			assert.Equal(t, tt.matched, matched)
			if matched {
				assert.Equal(t, tt.endpoint, endpoint)
				if tt.capability != "" {
					assert.Equal(t, tt.capability, capability)
				}
			}
		})
	}
}

func TestParseMonitorResponse_fromURI(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"uri": "https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	}`)

	records := capture.ParseCaptureRecords(capture.EndpointRegistryMonitor, "/v1/monitor/npm", body, capture.CapabilityOSS)
	requireLenOneEntity(t, records, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
}

func TestParseIaCShareResponse(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"./main.tf": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		"./other.tf": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		"ok": true
	}`)

	records := capture.ParseCaptureRecords(capture.EndpointRegistryIaCShare, "/v1/iac-cli-share-results", body, capture.CapabilityIaC)
	assert.Len(t, records, 2)
}

func TestParseCreateTestRequest_requiresPublishReport(t *testing.T) {
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
	_, ok := capture.ParseCreateTestRequest(body)
	assert.False(t, ok)

	body = []byte(`{
		"data": {
			"attributes": {
				"config": {
					"publish_report": true,
					"scan_config": {"sast": {}}
				}
			}
		}
	}`)
	meta, ok := capture.ParseCreateTestRequest(body)
	assert.True(t, ok)
	assert.True(t, meta.PublishReport)
	assert.Equal(t, capture.CapabilityCode, meta.Capability)
}

func TestParseCreateTestRequest_dragonflyMonitor(t *testing.T) {
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
	meta, ok := capture.ParseCreateTestRequest(body)
	assert.True(t, ok)
	assert.True(t, meta.PublishReport)
	assert.Equal(t, capture.CapabilityOSS, meta.Capability)

	body = []byte(`{
		"data": {
			"attributes": {
				"config": {
					"monitor": false
				}
			}
		}
	}`)
	_, ok = capture.ParseCreateTestRequest(body)
	assert.False(t, ok)
}

func TestParseTestJobRedirectResponse(t *testing.T) {
	t.Parallel()

	const testID = "44444444-4444-4444-8444-444444444444"
	body := []byte(`{
		"data": {
			"relationships": {
				"test": {
					"data": {"id": "` + testID + `"}
				}
			}
		}
	}`)

	assert.Equal(t, testID, capture.ParseTestJobRedirectResponse(body))
	assert.Equal(t, "22222222-2222-4222-8222-222222222222", capture.JobIDFromGetPath("/hidden/orgs/11111111-1111-4111-8111-111111111111/test_jobs/22222222-2222-4222-8222-222222222222"))
}

func TestParseCreateTestRequest_codeHiddenReport(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"data": {
			"type": "test",
			"attributes": {
				"configuration": {
					"output": {
						"report": true,
						"project_name": "billing-test-goof"
					}
				}
			}
		}
	}`)
	meta, ok := capture.ParseCreateTestRequest(body)
	assert.True(t, ok)
	assert.True(t, meta.PublishReport)
	assert.Equal(t, capture.CapabilityCode, meta.Capability)
}

func TestParseDeeproxyReportResponse_completeUploadResult(t *testing.T) {
	t.Parallel()

	const (
		reportID  = "55555555-5555-4555-8555-555555555555"
		projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	)
	path := "/report/" + reportID
	body := []byte(`{
		"status": "COMPLETE",
		"uploadResult": {
			"projectId": "` + projectID + `",
			"snapshotId": "28831237-953d-4baa-ba5f-2a6b01ba5b94"
		}
	}`)

	records := capture.ParseCaptureRecords(capture.EndpointDeeproxyReport, path, body, capture.CapabilityCode)
	requireLenOneEntity(t, records, projectID)
	assert.Equal(t, capture.CapabilityCode, records[0].Capability)
}

func TestParseDeeproxyReportResponse_ignoresIncompleteStatus(t *testing.T) {
	t.Parallel()

	path := "/report/55555555-5555-4555-8555-555555555555"
	body := []byte(`{
		"status": "IN_PROGRESS",
		"uploadResult": {"projectId": "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"}
	}`)

	records := capture.ParseCaptureRecords(capture.EndpointDeeproxyReport, path, body, capture.CapabilityCode)
	assert.Empty(t, records)
}

func TestParseDeeproxyReportResponse_requiresProjectID(t *testing.T) {
	t.Parallel()

	path := "/report/55555555-5555-4555-8555-555555555555"
	body := []byte(`{"status": "COMPLETE", "uploadResult": {}}`)

	records := capture.ParseCaptureRecords(capture.EndpointDeeproxyReport, path, body, capture.CapabilityCode)
	assert.Empty(t, records)
}

func TestParseDeeproxyReportResponse_projectIDSnakeCase(t *testing.T) {
	t.Parallel()

	const projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	path := "/report/55555555-5555-4555-8555-555555555555"
	body := []byte(`{
		"status": "COMPLETE",
		"uploadResult": {
			"project_id": "` + projectID + `"
		}
	}`)

	records := capture.ParseCaptureRecords(capture.EndpointDeeproxyReport, path, body, capture.CapabilityCode)
	requireLenOneEntity(t, records, projectID)
}

func TestParseDeeproxyReportResponse_truncatedBodyPrefix(t *testing.T) {
	t.Parallel()

	path := "/report/55555555-5555-4555-8555-555555555555"
	projectID := "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	// Simulates a 64 KiB read that cuts mid-SARIF (invalid JSON, but prefix has billing fields).
	body := []byte(`{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `"` + `,"analysisResult":{"type":"sarif","data":"` + strings.Repeat("x", 100) + `"`)

	records := capture.ParseCaptureRecords(capture.EndpointDeeproxyReport, path, body, capture.CapabilityCode)
	requireLenOneEntity(t, records, projectID)
}

func TestParseGetTestResponse_completedProjectEntity(t *testing.T) {
	t.Parallel()

	path := "/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222"
	body := []byte(`{
		"data": {
			"attributes": {
				"state": {"execution": "completed"},
				"subject_locators": [
					{"type": "project_entity", "project_id": "33333333-3333-4333-8333-333333333333"}
				]
			}
		}
	}`)

	records := capture.ParseCaptureRecords(capture.EndpointTestGet, path, body, capture.CapabilityOSS)
	requireLenOneEntity(t, records, "33333333-3333-4333-8333-333333333333")
}

func TestParseGetComponentsResponse_sastWebuiProject(t *testing.T) {
	t.Parallel()

	path := "/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222/components"
	body := []byte(`{
		"data": [{
			"attributes": {
				"type": "sast",
				"success": true,
				"webui": {"project_id": "44444444-4444-4444-8444-444444444444"}
			}
		}]
	}`)

	records := capture.ParseCaptureRecords(capture.EndpointTestComponents, path, body, capture.CapabilityCode)
	requireLenOneEntity(t, records, "44444444-4444-4444-8444-444444444444")
}

func TestParseAIBOMUploadRequest_fromFixture(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile(filepath.Join("testdata", "aibom_upload_request.json"))
	require.NoError(t, err)

	revisionID, ok := capture.ParseAIBOMUploadRequest(body)
	assert.True(t, ok)
	assert.Equal(t, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", revisionID)

	record := capture.AIBOMUploadRecord("/rest/orgs/org/ai_boms/upload", revisionID)
	assert.Equal(t, capture.CapabilityAIBOM, record.Capability)
	assert.Equal(t, capture.EntityTypeRevision, record.EntityType)
	assert.Equal(t, revisionID, record.EntityID)
}

func requireLenOneEntity(t *testing.T, records []capture.Record, entityID string) {
	t.Helper()
	if assert.Len(t, records, 1) {
		assert.Equal(t, entityID, records[0].EntityID)
		assert.Equal(t, capture.EntityTypeProject, records[0].EntityType)
	}
}
