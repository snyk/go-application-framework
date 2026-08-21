package contributor_capture

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	monitorPathPattern    = regexp.MustCompile(`(?i)^/v1/monitor(?:/|$)`)
	monitorDepsPattern    = regexp.MustCompile(`(?i)^/v1/monitor-dependencies(?:/|$)`)
	iacSharePattern       = regexp.MustCompile(`(?i)^/v1/iac-cli-share-results(?:/|$)`)
	createTestPathPattern = regexp.MustCompile(`(?i)^/hidden/orgs/[0-9a-fA-F-]{36}/tests$`)
	componentsPathPattern = regexp.MustCompile(`(?i)^/hidden/orgs/[0-9a-fA-F-]{36}/tests/([0-9a-fA-F-]{36})/components$`)
	aiBomUploadPattern    = regexp.MustCompile(`(?i)^/rest/orgs/[0-9a-fA-F-]{36}/ai_boms/upload$`)
)

// EndpointKind identifies which known product-API request/response shape a request matches.
type EndpointKind int

const (
	EndpointNone EndpointKind = iota
	EndpointRegistryMonitor
	EndpointRegistryIaCShare
	EndpointTestCreate
	EndpointTestComponents
	EndpointAIBomUpload
)

// classifyEndpoint uses a requests path and method to determine if it's a kind
// that contributor capture needs to run on.
func classifyEndpoint(method, path string) (EndpointKind, bool) {
	path = normalizePath(path)
	switch method {
	case http.MethodPut:
		if monitorPathPattern.MatchString(path) || monitorDepsPattern.MatchString(path) {
			return EndpointRegistryMonitor, true
		}
	case http.MethodPost:
		if iacSharePattern.MatchString(path) {
			return EndpointRegistryIaCShare, true
		}
		if createTestPathPattern.MatchString(path) {
			return EndpointTestCreate, true
		}
		if aiBomUploadPattern.MatchString(path) {
			return EndpointAIBomUpload, true
		}
	case http.MethodGet:
		if componentsPathPattern.MatchString(path) {
			return EndpointTestComponents, true
		}
	}

	return EndpointNone, false
}

// testIDFromPath extracts the test UUID from a GET .../tests/{id}/components
// path, given the EndpointKind already determined by classifyEndpoint.
func testIDFromPath(path string) string {
	path = normalizePath(path)
	return firstSubmatchUUID(componentsPathPattern, path)
}

func firstSubmatchUUID(pattern *regexp.Regexp, path string) string {
	matches := pattern.FindStringSubmatch(path)
	if len(matches) < 2 {
		return ""
	}
	return parseUUID(matches[1])
}

func parseUUID(value string) string {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return parsed.String()
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}
