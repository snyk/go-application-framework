package contributor_capture

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
)

const (
	orgPathPrefix     = "/hidden/orgs/"
	testsSegment      = "/tests"
	componentsSegment = "/components"
	uuidLen           = 36
)

// isValidUUID checks if a string is a valid UUID without allocating.
func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// EndpointKind identifies which known product-API request/response shape a request matches.
type endpointKind int

const (
	endpointNone endpointKind = iota
	endpointRegistryMonitor
	endpointRegistryIaCShare
	endpointTestCreate
	endpointTestComponents
	endpointAIBomUpload
	endpointDeeproxyReport
)

// classifyEndpoint uses a requests path and method to determine if it's a kind
// that contributor capture needs to run on.
func classifyEndpoint(method, path string) (endpointKind, bool) {
	path = normalizePath(path)
	switch method {
	case http.MethodPut:
		if isMonitorPath(path) || isMonitorDepsPath(path) {
			return endpointRegistryMonitor, true
		}
	case http.MethodPost:
		if isIaCSharePath(path) {
			return endpointRegistryIaCShare, true
		}
		if isCreateTestPath(path) {
			return endpointTestCreate, true
		}
		if isAIBomUploadPath(path) {
			return endpointAIBomUpload, true
		}
	case http.MethodGet:
		if isDeeproxyReportPath(path) {
			return endpointDeeproxyReport, true
		}
		if isComponentsPath(path) {
			return endpointTestComponents, true
		}
	}

	return endpointNone, false
}

// isMonitorPath matches PUT /v1/monitor or /v1/monitor/{any-path}.
func isMonitorPath(p string) bool {
	return hasPrefixCaseInsensitive(p, "/v1/monitor") && isPathEnd(p, len("/v1/monitor"))
}

// isMonitorDepsPath matches PUT /v1/monitor-dependencies or /v1/monitor-dependencies/{any-path}.
func isMonitorDepsPath(p string) bool {
	return hasPrefixCaseInsensitive(p, "/v1/monitor-dependencies") && isPathEnd(p, len("/v1/monitor-dependencies"))
}

// isIaCSharePath matches POST /v1/iac-cli-share-results or /v1/iac-cli-share-results/{any-path}.
func isIaCSharePath(p string) bool {
	return hasPrefixCaseInsensitive(p, "/v1/iac-cli-share-results") && isPathEnd(p, len("/v1/iac-cli-share-results"))
}

// isCreateTestPath matches POST /hidden/orgs/{uuid}/tests (exactly).
func isCreateTestPath(p string) bool {
	if len(p) != len(orgPathPrefix)+uuidLen+len(testsSegment) {
		return false
	}
	return hasOrgUUIDPrefix(p) && hasSuffixCaseInsensitive(p, testsSegment)
}

// isComponentsPath matches GET /hidden/orgs/{uuid}/tests/{uuid}/components (exactly).
func isComponentsPath(p string) bool {
	if len(p) != len(orgPathPrefix)+uuidLen+len(testsSegment)+1+uuidLen+len(componentsSegment) {
		return false
	}
	if !hasOrgUUIDPrefix(p) {
		return false
	}
	rest := p[len(orgPathPrefix)+uuidLen:]
	if !hasPrefixCaseInsensitive(rest, testsSegment+"/") {
		return false
	}
	testIDStart := len(testsSegment) + 1
	return isValidUUID(rest[testIDStart:testIDStart+uuidLen]) &&
		hasSuffixCaseInsensitive(rest, componentsSegment)
}

// hasOrgUUIDPrefix reports whether p starts with /hidden/orgs/{uuid}.
func hasOrgUUIDPrefix(p string) bool {
	if !hasPrefixCaseInsensitive(p, orgPathPrefix) {
		return false
	}
	return isValidUUID(p[len(orgPathPrefix) : len(orgPathPrefix)+uuidLen])
}

// isAIBomUploadPath matches POST /rest/orgs/{uuid}/ai_boms/upload (exactly).
func isAIBomUploadPath(p string) bool {
	const prefix = "/rest/orgs/"
	const suffix = "/ai_boms/upload"
	if !hasPrefixCaseInsensitive(p, prefix) {
		return false
	}
	uuidEnd := len(prefix) + 36
	if len(p) != len(prefix)+36+len(suffix) {
		return false
	}
	if !hasSuffixCaseInsensitive(p[uuidEnd:], suffix) {
		return false
	}
	return isValidUUID(p[len(prefix):uuidEnd])
}

// isDeeproxyReportPath matches GET /report/{uuid} or /report/{uuid}/ (exactly, ignoring trailing slash).
func isDeeproxyReportPath(p string) bool {
	const prefix = "/report/"
	if !hasPrefixCaseInsensitive(p, prefix) {
		return false
	}
	remaining := p[len(prefix):]
	if remaining == "" {
		return false
	}
	if remaining[len(remaining)-1] == '/' {
		remaining = remaining[:len(remaining)-1]
	}
	return isValidUUID(remaining)
}

func isPathEnd(p string, idx int) bool {
	return len(p) == idx || (len(p) > idx && p[idx] == '/')
}

func hasPrefixCaseInsensitive(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(s[:len(prefix)], prefix)
}

func hasSuffixCaseInsensitive(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return strings.EqualFold(s[len(s)-len(suffix):], suffix)
}

// testIDFromPath extracts the test UUID from a GET .../tests/{id}/components
// path, given the EndpointKind already determined by classifyEndpoint.
func testIDFromPath(path string) string {
	path = normalizePath(path)
	if !isComponentsPath(path) {
		return ""
	}
	testIDStart := len(orgPathPrefix) + uuidLen + len(testsSegment) + 1
	return parseUUID(path[testIDStart : testIDStart+uuidLen])
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
	if idx := strings.IndexAny(path, "?#"); idx >= 0 {
		path = path[:idx]
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}
