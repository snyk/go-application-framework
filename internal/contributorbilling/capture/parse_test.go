package capture_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
			name:     "get test",
			method:   "GET",
			path:     "/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222",
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

func requireLenOneEntity(t *testing.T, records []capture.Record, entityID string) {
	t.Helper()
	if assert.Len(t, records, 1) {
		assert.Equal(t, entityID, records[0].EntityID)
		assert.Equal(t, capture.EntityTypeProject, records[0].EntityType)
	}
}
