package contributor_capture_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	cc "github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
)

func TestClassifyEndpoint_PathPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		method   string
		path     string
		endpoint cc.EndpointKind
		matched  bool
	}{
		// Monitor patterns: PUT /v1/monitor or /v1/monitor/{path}
		{"monitor base", "PUT", "/v1/monitor", cc.EndpointRegistryMonitor, true},
		{"monitor npm", "PUT", "/v1/monitor/npm", cc.EndpointRegistryMonitor, true},
		{"monitor with query", "PUT", "/v1/monitor/npm?foo=bar", cc.EndpointRegistryMonitor, true},
		{"monitor wrong method", "GET", "/v1/monitor/npm", cc.EndpointNone, false},

		// Monitor deps patterns: PUT /v1/monitor-dependencies or /v1/monitor-dependencies/{path}
		{"monitor deps", "PUT", "/v1/monitor-dependencies", cc.EndpointRegistryMonitor, true},
		{"monitor deps with path", "PUT", "/v1/monitor-dependencies/npm", cc.EndpointRegistryMonitor, true},

		// IaC share patterns: POST /v1/iac-cli-share-results or /v1/iac-cli-share-results/{path}
		{"iac share", "POST", "/v1/iac-cli-share-results", cc.EndpointRegistryIaCShare, true},
		{"iac share with path", "POST", "/v1/iac-cli-share-results/subpath", cc.EndpointRegistryIaCShare, true},

		// Create test pattern: POST /hidden/orgs/{uuid}/tests (exactly)
		{"create test", "POST", "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests", cc.EndpointTestCreate, true},
		{"create test with query", "POST", "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests?version=2024", cc.EndpointTestCreate, true},
		{"create test with trailing slash", "POST", "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/", cc.EndpointNone, false},
		{"create test invalid uuid", "POST", "/hidden/orgs/not-a-uuid/tests", cc.EndpointNone, false},
		{"create test without hidden prefix", "POST", "/orgs/11111111-1111-4111-8111-111111111111/tests", cc.EndpointNone, false},

		// Components pattern: GET /hidden/orgs/{uuid}/tests/{uuid}/components (exactly)
		{"get components", "GET", "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222/components", cc.EndpointTestComponents, true},
		{"components with fragment", "GET", "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222/components#section", cc.EndpointTestComponents, true},
		{"get test without components", "GET", "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222", cc.EndpointNone, false},
		{"components with invalid uuid", "GET", "/hidden/orgs/11111111-1111-4111-8111-111111111111/tests/not-a-uuid/components", cc.EndpointNone, false},
		{"components without hidden prefix", "GET", "/orgs/11111111-1111-4111-8111-111111111111/tests/22222222-2222-4222-8222-222222222222/components", cc.EndpointNone, false},

		// AI BOM upload pattern: POST /rest/orgs/{uuid}/ai_boms/upload (exactly)
		{"ai bom upload", "POST", "/rest/orgs/11111111-1111-4111-8111-111111111111/ai_boms/upload", cc.EndpointAIBomUpload, true},
		{"ai bom upload wrong method", "GET", "/rest/orgs/11111111-1111-4111-8111-111111111111/ai_boms/upload", cc.EndpointNone, false},
		{"ai bom non-upload subpath", "POST", "/rest/orgs/11111111-1111-4111-8111-111111111111/ai_boms/upload/extra", cc.EndpointNone, false},

		// Deeproxy report pattern: GET /report/{uuid} or /report/{uuid}/
		{"deeproxy report", "GET", "/report/55555555-5555-4555-8555-555555555555", cc.EndpointDeeproxyReport, true},
		{"deeproxy report trailing slash", "GET", "/report/55555555-5555-4555-8555-555555555555/", cc.EndpointDeeproxyReport, true},
		{"deeproxy report with query", "GET", "/report/55555555-5555-4555-8555-555555555555?poll=1", cc.EndpointDeeproxyReport, true},

		// Non-matching paths
		{"analytics ignored", "POST", "/v1/analytics/cli", cc.EndpointNone, false},
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
