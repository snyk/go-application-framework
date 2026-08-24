package contributor_capture_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	cc "github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
)

func TestClassifyEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		method   string
		path     string
		endpoint cc.EndpointKind
		matched  bool
	}{
		{
			name:     "oss monitor",
			method:   "PUT",
			path:     "/v1/monitor/npm",
			endpoint: cc.EndpointRegistryMonitor,
			matched:  true,
		},
		{
			name:     "monitor dependencies",
			method:   "PUT",
			path:     "/v1/monitor-dependencies",
			endpoint: cc.EndpointRegistryMonitor,
			matched:  true,
		},
		{
			name:     "iac share",
			method:   "POST",
			path:     "/v1/iac-cli-share-results",
			endpoint: cc.EndpointRegistryIaCShare,
			matched:  true,
		},
		{
			name:     "create test",
			method:   "POST",
			path:     "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests",
			endpoint: cc.EndpointTestCreate,
			matched:  true,
		},
		{
			name:     "ai bom upload",
			method:   "POST",
			path:     "/rest/orgs/11111111-1111-4111-8111-111111111111/ai_boms/upload",
			endpoint: cc.EndpointAIBomUpload,
			matched:  true,
		},
		{
			name:    "ai bom upload wrong method",
			method:  "GET",
			path:    "/rest/orgs/11111111-1111-4111-8111-111111111111/ai_boms/upload",
			matched: false,
		},
		{
			name:    "ai bom non-upload subpath ignored",
			method:  "POST",
			path:    "/rest/orgs/11111111-1111-4111-8111-111111111111/ai_boms/upload/extra",
			matched: false,
		},
		{
			name:     "get components",
			method:   "GET",
			path:     "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222/components",
			endpoint: cc.EndpointTestComponents,
			matched:  true,
		},
		{
			name:     "deeproxy legacy code report",
			method:   "GET",
			path:     "/report/55555555-5555-4555-8555-555555555555",
			endpoint: cc.EndpointDeeproxyReport,
			matched:  true,
		},
		{
			name:     "deeproxy legacy code report trailing slash",
			method:   "GET",
			path:     "/report/55555555-5555-4555-8555-555555555555/",
			endpoint: cc.EndpointDeeproxyReport,
			matched:  true,
		},
		{
			name:     "deeproxy legacy code report with query",
			method:   "GET",
			path:     "/report/55555555-5555-4555-8555-555555555555?poll=1",
			endpoint: cc.EndpointDeeproxyReport,
			matched:  true,
		},
		{
			name:    "analytics ignored",
			method:  "POST",
			path:    "/v1/analytics/cli",
			matched: false,
		},
		{
			name:    "get test without components not matched",
			method:  "GET",
			path:    "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222",
			matched: false,
		},
		{
			name:    "get components with non-uuid id",
			method:  "GET",
			path:    "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/not-a-uuid/components",
			matched: false,
		},
		{
			name:    "create test with trailing slash",
			method:  "POST",
			path:    "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/",
			matched: false,
		},
		{
			name:    "create test without hidden prefix not matched",
			method:  "POST",
			path:    "/orgs/11111111-1111-4111-8111-111111111111/tests",
			matched: false,
		},
		{
			name:    "get components without hidden prefix not matched",
			method:  "GET",
			path:    "/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222/components",
			matched: false,
		},
		{
			name:    "monitor wrong method",
			method:  "GET",
			path:    "/v1/monitor/npm",
			matched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			endpoint, matched := cc.ClassifyEndpoint(tt.method, tt.path)
			assert.Equal(t, tt.matched, matched)
			if matched {
				assert.Equal(t, tt.endpoint, endpoint)
			}
		})
	}
}
